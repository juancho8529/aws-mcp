import pytest
import time
import httpx
from unittest.mock import Mock, call, patch
from awslabs.openapi_mcp_server.api.config import Config
from awslabs.openapi_mcp_server.auth.auth_errors import (
    ConfigurationError,
    MissingCredentialsError,
    InvalidCredentialsError,
    ExpiredTokenError
)
from awslabs.openapi_mcp_server.auth.oauth_device_auth import (
    OAuthDeviceAuthProvider,
    OAuthDeviceHTTPXAuth,
)


def create_config() -> Config:
    config = Config()
    config.auth_type = 'oauth_device'
    config.auth_oauth_device_client_id = 'test-client'
    config.auth_oauth_device_authorization_endpoint = (
        'https://auth.example.com/device'
    )
    config.auth_oauth_device_token_endpoint = (
        'https://auth.example.com/token'
    )
    config.auth_oauth_device_scopes = 'openid profile'
    config.auth_oauth_device_request_format = 'form'
    return config


def test_oauth_device_provider_valid_configuration():
    config = create_config()

    provider = OAuthDeviceAuthProvider(config)

    assert provider.is_configured()
    assert provider.provider_name == 'oauth_device'


def test_oauth_device_provider_accepts_json_request_format():
    config = create_config()
    config.auth_oauth_device_request_format = 'json'

    provider = OAuthDeviceAuthProvider(config)

    assert provider.is_configured()


def test_oauth_device_provider_requires_client_id():
    config = create_config()
    config.auth_oauth_device_client_id = ''

    with pytest.raises(MissingCredentialsError):
        OAuthDeviceAuthProvider(config)


def test_oauth_device_provider_requires_authorization_endpoint():
    config = create_config()
    config.auth_oauth_device_authorization_endpoint = ''

    with pytest.raises(MissingCredentialsError):
        OAuthDeviceAuthProvider(config)


def test_oauth_device_provider_requires_token_endpoint():
    config = create_config()
    config.auth_oauth_device_token_endpoint = ''

    with pytest.raises(MissingCredentialsError):
        OAuthDeviceAuthProvider(config)


def test_oauth_device_provider_rejects_invalid_request_format():
    config = create_config()
    config.auth_oauth_device_request_format = 'xml'

    with pytest.raises(ConfigurationError):
        OAuthDeviceAuthProvider(config)


def prepare_provider_for_polling() -> OAuthDeviceAuthProvider:
    config = create_config()

    provider = OAuthDeviceAuthProvider(config)

    provider._device_code = 'device-123'
    provider._device_code_expires_at = time.time() + 600
    provider._poll_interval = 5

    return provider

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_start_device_authorization_form(mock_post):
    config = create_config()

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'device_code': 'device-123',
        'user_code': 'ABCD-1234',
        'verification_uri': 'https://auth.example.com/verify',
        'expires_in': 600,
        'interval': 5,
    }

    mock_post.return_value = response

    provider = OAuthDeviceAuthProvider(config)

    result = provider._start_device_authorization()

    mock_post.assert_called_once_with(
        'https://auth.example.com/device',
        data={
            'client_id': 'test-client',
            'scope': 'openid profile',
        },
        timeout=30,
    )

    assert result['device_code'] == 'device-123'
    assert provider._device_code == 'device-123'
    assert provider._user_code == 'ABCD-1234'
    assert (
        provider._verification_uri
        == 'https://auth.example.com/verify'
    )
    assert provider._poll_interval == 5

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_start_device_authorization_json(mock_post):
    config = create_config()

    config.auth_oauth_device_request_format = 'json'
    config.auth_oauth_device_scopes = ''

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'device_code': 'device-456',
        'user_code': 'WXYZ-9876',
        'verification_uri': 'https://auth.example.com/verify',
        'expires_in': 600,
        'interval': None,
    }

    mock_post.return_value = response

    provider = OAuthDeviceAuthProvider(config)

    provider._start_device_authorization()

    mock_post.assert_called_once_with(
        'https://auth.example.com/device',
        json={
            'client_id': 'test-client',
        },
        timeout=30,
    )

    assert provider._device_code == 'device-456'

    # Default RFC polling interval.
    assert provider._poll_interval == 5

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_start_device_authorization_http_error(mock_post):
    config = create_config()

    response = Mock()
    response.status_code = 400
    response.text = 'bad request'

    mock_post.return_value = response

    provider = OAuthDeviceAuthProvider(config)

    with pytest.raises(InvalidCredentialsError):
        provider._start_device_authorization()

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_start_device_authorization_missing_fields(mock_post):
    config = create_config()

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'device_code': 'device-123',
    }

    mock_post.return_value = response

    provider = OAuthDeviceAuthProvider(config)

    with pytest.raises(InvalidCredentialsError):
        provider._start_device_authorization()

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_poll_for_token_success(mock_post):
    provider = prepare_provider_for_polling()

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'access_token': 'access-123',
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': 'refresh-123',
    }

    mock_post.return_value = response

    result = provider._poll_for_token()

    assert result['access_token'] == 'access-123'

    assert provider._token == 'access-123'
    assert provider._refresh_token_value == 'refresh-123'

    assert provider.get_auth_headers() == {}

    auth = provider.get_httpx_auth()
    
    request = httpx.Request(
        'GET',
        'https://api.example.com/resource',
    )
    
    flow = auth.sync_auth_flow(request)
    
    authenticated_request = next(flow)
    
    assert authenticated_request.headers['Authorization'] == (
        'Bearer access-123'
    )

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.time.sleep'
)
@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_poll_for_token_authorization_pending(
    mock_post,
    mock_sleep,
):
    provider = prepare_provider_for_polling()

    pending = Mock()
    pending.status_code = 400
    pending.json.return_value = {
        'error': 'authorization_pending'
    }

    success = Mock()
    success.status_code = 200
    success.json.return_value = {
        'access_token': 'access-123',
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    mock_post.side_effect = [
        pending,
        success,
    ]

    provider._poll_for_token()

    assert mock_post.call_count == 2

    mock_sleep.assert_called_once_with(5)

    assert provider._token == 'access-123'

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.time.sleep'
)
@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_poll_for_token_slow_down(
    mock_post,
    mock_sleep,
):
    provider = prepare_provider_for_polling()

    slow_down = Mock()
    slow_down.status_code = 400
    slow_down.json.return_value = {
        'error': 'slow_down'
    }

    success = Mock()
    success.status_code = 200
    success.json.return_value = {
        'access_token': 'access-123',
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    mock_post.side_effect = [
        slow_down,
        success,
    ]

    provider._poll_for_token()

    assert provider._poll_interval == 10

    mock_sleep.assert_called_once_with(10)

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_poll_for_token_access_denied(mock_post):
    provider = prepare_provider_for_polling()

    response = Mock()
    response.status_code = 400
    response.json.return_value = {
        'error': 'access_denied'
    }

    mock_post.return_value = response

    with pytest.raises(InvalidCredentialsError):
        provider._poll_for_token()

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_poll_for_token_exchange_style_pending_error(mock_post):
    provider = prepare_provider_for_polling()

    pending = Mock()
    pending.status_code = 400
    pending.json.return_value = {
        'detail': 'authorization_pending'
    }

    success = Mock()
    success.status_code = 200
    success.json.return_value = {
        'access_token': 'access-456',
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    mock_post.side_effect = [
        pending,
        success,
    ]

    with patch(
        'awslabs.openapi_mcp_server.auth.oauth_device_auth.time.sleep'
    ):
        provider._poll_for_token()

    assert provider._token == 'access-456'

def test_poll_for_token_expired_device_code():
    provider = prepare_provider_for_polling()

    provider._device_code_expires_at = time.time() - 1

    with pytest.raises(ExpiredTokenError):
        provider._poll_for_token()

def prepare_provider_with_token() -> OAuthDeviceAuthProvider:
    provider = prepare_provider_for_polling()

    provider._token = 'access-old'
    provider._refresh_token_value = 'refresh-old'
    provider._token_expires_at = time.time() + 60

    # Regenerate BearerAuthProvider headers for access-old.
    provider._initialize_auth()

    return provider

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_refresh_access_token_success(mock_post):
    provider = prepare_provider_with_token()

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'access_token': 'access-new',
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': 'refresh-new',
    }

    mock_post.return_value = response

    provider._refresh_access_token()

    assert provider._token == 'access-new'
    assert provider._refresh_token_value == 'refresh-new'

    assert provider._token == 'access-new'
    assert provider._refresh_token_value == 'refresh-new'

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_refresh_access_token_json(mock_post):
    config = create_config()
    config.auth_oauth_device_request_format = 'json'

    provider = OAuthDeviceAuthProvider(config)

    provider._refresh_token_value = 'refresh-old'

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'access_token': 'access-new',
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    mock_post.return_value = response

    provider._refresh_access_token()

    mock_post.assert_called_once_with(
        'https://auth.example.com/token',
        json={
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh-old',
            'client_id': 'test-client',
        },
        timeout=30,
    )

    assert provider._token == 'access-new'

    # Server didn't rotate it, therefore keep existing token.
    assert provider._refresh_token_value == 'refresh-old'

def test_get_auth_headers_returns_no_static_headers():
    provider = prepare_provider_with_token()

    assert provider.get_auth_headers() == {}

def test_httpx_auth_expired_without_refresh_token():
    provider = prepare_provider_with_token()

    provider._refresh_token_value = None
    provider._token_expires_at = time.time() - 1

    auth = provider.get_httpx_auth()

    request = httpx.Request(
        'GET',
        'https://api.example.com/resource',
    )

    flow = auth.sync_auth_flow(request)

    with pytest.raises(ExpiredTokenError):
        next(flow)

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_refresh_access_token_invalid_grant(mock_post):
    provider = prepare_provider_with_token()

    response = Mock()
    response.status_code = 400
    response.json.return_value = {
        'error': 'invalid_grant'
    }

    mock_post.return_value = response

    with pytest.raises(ExpiredTokenError):
        provider._refresh_access_token()

def test_get_httpx_auth_returns_dynamic_auth():
    config = create_config()

    provider = OAuthDeviceAuthProvider(config)

    auth = provider.get_httpx_auth()

    assert isinstance(auth, OAuthDeviceHTTPXAuth)

def test_httpx_auth_adds_current_access_token():
    provider = prepare_provider_with_token()

    provider._token_expires_at = time.time() + 3600

    auth = provider.get_httpx_auth()

    request = httpx.Request(
        'GET',
        'https://api.example.com/resource',
    )

    flow = auth.sync_auth_flow(request)

    authenticated_request = next(flow)

    assert authenticated_request.headers['Authorization'] == (
        'Bearer access-old'
    )

@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
def test_httpx_auth_refreshes_expiring_token(mock_post):
    provider = prepare_provider_with_token()

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'access_token': 'access-new',
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    mock_post.return_value = response

    auth = provider.get_httpx_auth()

    request = httpx.Request(
        'GET',
        'https://api.example.com/resource',
    )

    flow = auth.sync_auth_flow(request)

    authenticated_request = next(flow)

    assert authenticated_request.headers['Authorization'] == (
        'Bearer access-new'
    )

    assert provider._token == 'access-new'

    assert mock_post.call_count == 1

@pytest.mark.asyncio
@patch(
    'awslabs.openapi_mcp_server.auth.oauth_device_auth.requests.post'
)
async def test_httpx_async_auth_refreshes_expiring_token(mock_post):
    provider = prepare_provider_with_token()

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        'access_token': 'access-async',
        'token_type': 'Bearer',
        'expires_in': 3600,
    }

    mock_post.return_value = response

    auth = provider.get_httpx_auth()

    request = httpx.Request(
        'GET',
        'https://api.example.com/resource',
    )

    flow = auth.async_auth_flow(request)

    authenticated_request = await anext(flow)

    assert authenticated_request.headers['Authorization'] == (
        'Bearer access-async'
    )

    assert provider._token == 'access-async'