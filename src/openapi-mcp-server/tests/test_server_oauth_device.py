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
"""Tests for OAuth Device wiring in server.py."""

import pytest
from awslabs.openapi_mcp_server.api.config import Config
from awslabs.openapi_mcp_server.auth.oauth_device_middleware import (
    OAuthDeviceAuthMiddleware,
)
from awslabs.openapi_mcp_server.server import create_mcp_server_async, main
from unittest.mock import MagicMock, patch


def _oauth_device_config(**overrides) -> Config:
    defaults = {
        'api_name': 'Test',
        'api_base_url': 'https://example.com',
        'api_spec_url': 'https://example.com/spec.json',
        'auth_type': 'oauth_device',
        'auth_oauth_device_client_id': 'test-client',
        'auth_oauth_device_authorization_endpoint': 'https://auth.example.com/device',
        'auth_oauth_device_token_endpoint': 'https://auth.example.com/token',
        'auth_oauth_device_scopes': 'openid profile',
        'auth_oauth_device_request_format': 'form',
    }
    defaults.update(overrides)
    return Config(**defaults)


def _mock_oauth_provider() -> MagicMock:
    provider = MagicMock()
    provider.is_configured.return_value = True
    provider.provider_name = 'oauth_device'
    provider.get_auth_headers.return_value = {}
    provider.get_auth_params.return_value = {}
    provider.get_auth_cookies.return_value = {}
    provider.get_httpx_auth.return_value = None
    return provider


@pytest.mark.asyncio
async def test_oauth_device_adds_middleware():
    """oauth_device auth registers OAuthDeviceAuthMiddleware on the server."""
    config = _oauth_device_config()
    mock_server = MagicMock()
    mock_provider = _mock_oauth_provider()

    with (
        patch('awslabs.openapi_mcp_server.server.load_openapi_spec') as mock_load,
        patch('awslabs.openapi_mcp_server.server.validate_openapi_spec', return_value=True),
        patch('awslabs.openapi_mcp_server.server.HttpClientFactory.create_client'),
        patch('awslabs.openapi_mcp_server.server.FastMCP') as mock_fastmcp,
        patch('awslabs.openapi_mcp_server.auth.register.register_provider_by_type'),
        patch(
            'awslabs.openapi_mcp_server.auth.is_auth_type_available',
            return_value=True,
        ),
        patch(
            'awslabs.openapi_mcp_server.auth.get_auth_provider',
            return_value=mock_provider,
        ),
        patch('awslabs.openapi_mcp_server.server.MCPPromptManager') as mock_pm,
    ):
        mock_load.return_value = {
            'openapi': '3.0.0',
            'info': {'title': 'Test API', 'version': '1.0.0'},
            'paths': {},
        }
        mock_fastmcp.from_openapi.return_value = mock_server

        async def _gen(*args, **kwargs):
            return None

        mock_pm.return_value.generate_prompts = _gen

        await create_mcp_server_async(config)

        mock_server.add_middleware.assert_called_once()
        middleware = mock_server.add_middleware.call_args.args[0]
        assert isinstance(middleware, OAuthDeviceAuthMiddleware)


@pytest.mark.asyncio
async def test_non_oauth_device_does_not_add_middleware():
    """Other auth types do not register OAuth Device middleware."""
    config = Config(
        api_name='Test',
        api_base_url='https://example.com',
        api_spec_url='https://example.com/spec.json',
        auth_type='bearer',
        auth_token='token',
    )
    mock_server = MagicMock()

    with (
        patch('awslabs.openapi_mcp_server.server.load_openapi_spec') as mock_load,
        patch('awslabs.openapi_mcp_server.server.validate_openapi_spec', return_value=True),
        patch('awslabs.openapi_mcp_server.server.HttpClientFactory.create_client'),
        patch('awslabs.openapi_mcp_server.server.FastMCP') as mock_fastmcp,
        patch('awslabs.openapi_mcp_server.auth.register.register_provider_by_type'),
        patch('awslabs.openapi_mcp_server.server.MCPPromptManager') as mock_pm,
    ):
        mock_load.return_value = {
            'openapi': '3.0.0',
            'info': {'title': 'Test API', 'version': '1.0.0'},
            'paths': {},
        }
        mock_fastmcp.from_openapi.return_value = mock_server

        async def _gen(*args, **kwargs):
            return None

        mock_pm.return_value.generate_prompts = _gen

        await create_mcp_server_async(config)

        mock_server.add_middleware.assert_not_called()


@patch('awslabs.openapi_mcp_server.server.create_mcp_server')
@patch('awslabs.openapi_mcp_server.server.load_config')
@patch('awslabs.openapi_mcp_server.server.asyncio.run')
@patch('awslabs.openapi_mcp_server.server.setup_signal_handlers')
@patch('awslabs.openapi_mcp_server.server.logger')
def test_main_parses_oauth_device_cli_args(
    mock_logger,
    mock_setup_signal_handlers,
    mock_asyncio_run,
    mock_load_config,
    mock_create_mcp_server,
):
    """CLI accepts oauth_device auth type and related OAuth Device flags."""
    captured = {}

    def _capture_load(args):
        captured['args'] = args
        config = MagicMock()
        config.transport = 'stdio'
        return config

    mock_load_config.side_effect = _capture_load
    mock_create_mcp_server.return_value = MagicMock()
    mock_asyncio_run.return_value = (0, 1, 0, 0)

    argv = [
        'openapi-mcp-server',
        '--auth-type',
        'oauth_device',
        '--auth-oauth-device-client-id',
        'cli-client',
        '--auth-oauth-device-authorization-endpoint',
        'https://auth.example.com/device',
        '--auth-oauth-device-token-endpoint',
        'https://auth.example.com/token',
        '--auth-oauth-device-scopes',
        'openid profile',
        '--auth-oauth-device-request-format',
        'json',
    ]

    with patch('sys.argv', argv):
        main()

    args = captured['args']
    assert args.auth_type == 'oauth_device'
    assert args.auth_oauth_device_client_id == 'cli-client'
    assert args.auth_oauth_device_authorization_endpoint == 'https://auth.example.com/device'
    assert args.auth_oauth_device_token_endpoint == 'https://auth.example.com/token'
    assert args.auth_oauth_device_scopes == 'openid profile'
    assert args.auth_oauth_device_request_format == 'json'
