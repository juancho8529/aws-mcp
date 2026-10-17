# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OAuth 2.0 Device Authorization authentication provider."""

import threading
import time
import requests
import asyncio
import httpx
from typing import Any, AsyncGenerator, Dict, Generator

from awslabs.openapi_mcp_server.api.config import Config
from awslabs.openapi_mcp_server.auth.auth_errors import (
    ConfigurationError,
    ExpiredTokenError,
    InvalidCredentialsError,
    MissingCredentialsError,
    NetworkError,
)
from awslabs.openapi_mcp_server.auth.bearer_auth import BearerAuthProvider

class OAuthDeviceHTTPXAuth(httpx.Auth):
    """HTTPX authentication adapter for OAuth Device Authorization."""

    def __init__(self, provider: 'OAuthDeviceAuthProvider'):
        self._provider = provider

    def sync_auth_flow(
        self,
        request: httpx.Request,
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """Authenticate synchronous HTTPX requests."""

        self._provider.ensure_access_token()

        request.headers['Authorization'] = (
            f'Bearer {self._provider._token}'
        )

        yield request

    async def async_auth_flow(
        self,
        request: httpx.Request,
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """Authenticate asynchronous HTTPX requests."""

        await asyncio.to_thread(
            self._provider.ensure_access_token
        )

        request.headers['Authorization'] = (
            f'Bearer {self._provider._token}'
        )

        yield request

class OAuthDeviceAuthProvider(BearerAuthProvider):
    """OAuth 2.0 Device Authorization authentication provider.

    This provider obtains and refreshes OAuth access tokens using the
    Device Authorization Grant and delegates bearer header generation
    to BearerAuthProvider.
    """

    def __init__(self, config: Config):
        """Initialize the OAuth Device Authorization provider."""
        self._client_id = config.auth_oauth_device_client_id
        self._authorization_endpoint = (
            config.auth_oauth_device_authorization_endpoint
        )
        self._token_endpoint = config.auth_oauth_device_token_endpoint
        self._scopes = (
            config.auth_oauth_device_scopes.split()
            if config.auth_oauth_device_scopes
            else []
        )
        self._request_format = config.auth_oauth_device_request_format.lower()

        # Token lifecycle state.
        self._token_expires_at = 0
        self._refresh_token_value = None
        self._token_lock = threading.RLock()

        self._device_code = None
        self._user_code = None
        self._verification_uri = None
        self._verification_uri_complete = None
        self._device_code_expires_at = 0
        self._poll_interval = 5

        # BearerAuthProvider requires a token during initialization.
        # The real access token will be acquired before authenticated
        # API requests are made.
        if not config.auth_token:
            config.auth_token = 'PENDING_OAUTH_DEVICE_TOKEN'
        
        self._httpx_auth = OAuthDeviceHTTPXAuth(self)
        super().__init__(config)

    def get_httpx_auth(self) -> httpx.Auth:
        """Get dynamic HTTPX authentication."""
    
        return self._httpx_auth

    def _validate_config(self) -> bool:
        """Validate OAuth Device Authorization configuration."""
        if not self._client_id:
            raise MissingCredentialsError(
                'OAuth Device Authorization requires a client ID',
                {
                    'help': (
                        'Provide a client ID using '
                        'AUTH_OAUTH_DEVICE_CLIENT_ID'
                    )
                },
            )

        if not self._authorization_endpoint:
            raise MissingCredentialsError(
                'OAuth Device Authorization requires an authorization endpoint',
                {
                    'help': (
                        'Provide an authorization endpoint using '
                        'AUTH_OAUTH_DEVICE_AUTHORIZATION_ENDPOINT'
                    )
                },
            )

        if not self._token_endpoint:
            raise MissingCredentialsError(
                'OAuth Device Authorization requires a token endpoint',
                {
                    'help': (
                        'Provide a token endpoint using '
                        'AUTH_OAUTH_DEVICE_TOKEN_ENDPOINT'
                    )
                },
            )

        if self._request_format not in ('form', 'json'):
            raise ConfigurationError(
                'OAuth Device Authorization request format must be form or json',
                {
                    'request_format': self._request_format,
                    'help': (
                        'Set AUTH_OAUTH_DEVICE_REQUEST_FORMAT '
                        'to form or json'
                    ),
                },
            )

        return super()._validate_config()

    def _log_validation_error(self) -> None:
        """Log OAuth Device Authorization validation errors."""
        # Validation errors already provide actionable configuration details.
        pass

    @property
    def provider_name(self) -> str:
        """Get the authentication provider name."""
        return 'oauth_device'

    def _start_device_authorization(self) -> Dict[str, Any]:
        """Start the OAuth Device Authorization flow."""
    
        payload = {
            'client_id': self._client_id,
        }
    
        if self._scopes:
            payload['scope'] = ' '.join(self._scopes)
    
        try:
            if self._request_format == 'json':
                response = requests.post(
                    self._authorization_endpoint,
                    json=payload,
                    timeout=30,
                )
            else:
                response = requests.post(
                    self._authorization_endpoint,
                    data=payload,
                    timeout=30,
                )
    
        except requests.RequestException as e:
            raise NetworkError(
                'Failed to connect to OAuth Device Authorization endpoint',
                {'error': str(e)},
            ) from e
    
        if response.status_code != 200:
            raise InvalidCredentialsError(
                'Failed to start OAuth Device Authorization flow',
                {
                    'status_code': response.status_code,
                    'error': response.text,
                },
            )
    
        try:
            data = response.json()
        except ValueError as e:
            raise InvalidCredentialsError(
                'OAuth Device Authorization endpoint returned invalid JSON',
                {'error': str(e)},
            ) from e
    
        required_fields = (
            'device_code',
            'user_code',
            'verification_uri',
            'expires_in',
        )
    
        missing_fields = [
            field
            for field in required_fields
            if field not in data
        ]
    
        if missing_fields:
            raise InvalidCredentialsError(
                'OAuth Device Authorization response is missing required fields',
                {'missing_fields': missing_fields},
            )
    
        self._device_code = data['device_code']
        self._user_code = data['user_code']
        self._verification_uri = data['verification_uri']
        self._verification_uri_complete = data.get(
            'verification_uri_complete'
        )
    
        expires_in = int(data['expires_in'])
        self._device_code_expires_at = time.time() + expires_in
    
        # RFC 8628 recommends 5 seconds when interval is omitted.
        self._poll_interval = int(data.get('interval') or 5)
    
        return data

    def _apply_token_response(self, data: Dict[str, Any]) -> None:
        """Apply a successful OAuth token response."""
    
        access_token = data.get('access_token')
    
        if not access_token:
            raise InvalidCredentialsError(
                'OAuth token response does not contain an access token'
            )
    
        token_type = data.get('token_type')
    
        if token_type and token_type.lower() != 'bearer':
            raise InvalidCredentialsError(
                'OAuth token response contains an unsupported token type',
                {'token_type': token_type},
            )
    
        expires_in = int(data.get('expires_in', 3600))
    
        self._token = access_token
        self._token_expires_at = time.time() + expires_in
    
        refresh_token = data.get('refresh_token')
        if refresh_token:
            self._refresh_token_value = refresh_token
    
        # BearerAuthProvider caches the Authorization header.
        # Regenerate it using the newly acquired access token.
        self._initialize_auth()

    @staticmethod
    def _extract_oauth_error(data: Dict[str, Any]) -> str | None:
        """Extract an OAuth error code from an error response."""
    
        error = data.get('error')
    
        if isinstance(error, str):
            return error
    
        # Some APIs expose the OAuth error code using a generic
        # "detail" field instead of the standard "error" field.
        detail = data.get('detail')
    
        if isinstance(detail, str):
            return detail
    
        return None

    def _poll_for_token(self) -> Dict[str, Any]:
        """Poll the OAuth token endpoint until authorization completes."""
    
        if not self._device_code:
            raise ConfigurationError(
                'Device authorization has not been started'
            )
    
        grant_type = (
            'urn:ietf:params:oauth:grant-type:device_code'
        )
    
        while True:
            if time.time() >= self._device_code_expires_at:
                raise ExpiredTokenError(
                    'OAuth device code has expired'
                )
    
            payload = {
                'grant_type': grant_type,
                'device_code': self._device_code,
                'client_id': self._client_id,
            }
    
            try:
                if self._request_format == 'json':
                    response = requests.post(
                        self._token_endpoint,
                        json=payload,
                        timeout=30,
                    )
                else:
                    response = requests.post(
                        self._token_endpoint,
                        data=payload,
                        timeout=30,
                    )
    
            except requests.RequestException as e:
                raise NetworkError(
                    'Failed to connect to OAuth token endpoint',
                    {'error': str(e)},
                ) from e
    
            try:
                data = response.json()
            except ValueError as e:
                raise InvalidCredentialsError(
                    'OAuth token endpoint returned invalid JSON',
                    {
                        'status_code': response.status_code,
                        'error': str(e),
                    },
                ) from e
    
            if response.status_code == 200:
                self._apply_token_response(data)
                return data
    
            error = self._extract_oauth_error(data)
    
            if error == 'authorization_pending':
                time.sleep(self._poll_interval)
                continue
    
            if error == 'slow_down':
                self._poll_interval += 5
                time.sleep(self._poll_interval)
                continue
    
            # RFC 8628 uses "expired_token".
            # Some implementations use "token_expired".
            if error in ('expired_token', 'token_expired'):
                raise ExpiredTokenError(
                    'OAuth device authorization expired',
                    {'error': error},
                )
    
            if error == 'access_denied':
                raise InvalidCredentialsError(
                    'OAuth device authorization was denied by the user',
                    {'error': error},
                )
    
            raise InvalidCredentialsError(
                'OAuth device token request failed',
                {
                    'status_code': response.status_code,
                    'error': error or response.text,
                },
            )

    def _refresh_access_token(self) -> Dict[str, Any]:
        """Refresh the OAuth access token using the refresh token."""
    
        if not self._refresh_token_value:
            raise ExpiredTokenError(
                'OAuth access token cannot be refreshed because no refresh token is available'
            )
    
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': self._refresh_token_value,
            'client_id': self._client_id,
        }
    
        try:
            if self._request_format == 'json':
                response = requests.post(
                    self._token_endpoint,
                    json=payload,
                    timeout=30,
                )
            else:
                response = requests.post(
                    self._token_endpoint,
                    data=payload,
                    timeout=30,
                )
    
        except requests.RequestException as e:
            raise NetworkError(
                'Failed to connect to OAuth token endpoint while refreshing token',
                {'error': str(e)},
            ) from e
    
        try:
            data = response.json()
        except ValueError as e:
            raise InvalidCredentialsError(
                'OAuth token endpoint returned invalid JSON while refreshing token',
                {
                    'status_code': response.status_code,
                    'error': str(e),
                },
            ) from e
    
        if response.status_code != 200:
            error = self._extract_oauth_error(data)
    
            if error == 'invalid_grant':
                raise ExpiredTokenError(
                    'OAuth refresh token is invalid or expired',
                    {'error': error},
                )
    
            raise InvalidCredentialsError(
                'OAuth access token refresh failed',
                {
                    'status_code': response.status_code,
                    'error': error or response.text,
                },
            )
    
        self._apply_token_response(data)
    
        return data

    def _is_token_expired_or_expiring_soon(self) -> bool:
        """Check whether the access token needs to be refreshed."""
    
        refresh_buffer_seconds = 300
    
        return (
            time.time() + refresh_buffer_seconds
            >= self._token_expires_at
        )

    def _check_and_refresh_token_if_needed(self) -> None:
        """Ensure that a valid access token is available."""
    
        with self._token_lock:
            if not self._is_token_expired_or_expiring_soon():
                return
    
            if self._refresh_token_value:
                self._refresh_access_token()
                return
    
            raise ExpiredTokenError(
                'OAuth access token is expired or unavailable '
                'and no refresh token is available'
            )

    def get_auth_headers(self) -> Dict[str, str]:
        """Return no static auth headers.
    
        OAuth Device Authorization uses a dynamic HTTPX Auth implementation
        so tokens can be refreshed between requests.
        """
    
        return {}

    def ensure_access_token(self) -> None:
        """Ensure that a valid OAuth access token is available.
    
        Refreshes the token when possible. Raises ExpiredTokenError when
        interactive authentication is required.
        """
    
        self._check_and_refresh_token_if_needed()
    
    
    def start_device_authorization(self) -> Dict[str, Any]:
        """Start an interactive OAuth Device Authorization flow."""
    
        return self._start_device_authorization()
    
    
    def complete_device_authorization(self) -> Dict[str, Any]:
        """Complete a previously started Device Authorization flow."""
    
        return self._poll_for_token()