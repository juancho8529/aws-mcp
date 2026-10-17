from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from fastmcp.exceptions import ToolError

from awslabs.openapi_mcp_server.auth.auth_errors import (
    ExpiredTokenError,
)
from awslabs.openapi_mcp_server.auth.oauth_device_middleware import (
    OAuthDeviceAuthMiddleware,
)

@pytest.mark.asyncio
async def test_valid_token_executes_tool_without_elicitation():
    provider = Mock()
    provider.ensure_access_token.return_value = None

    middleware = OAuthDeviceAuthMiddleware(provider)

    fastmcp_context = Mock()
    fastmcp_context.elicit = AsyncMock()

    context = SimpleNamespace(
        fastmcp_context=fastmcp_context,
    )

    call_next = AsyncMock(return_value='result')

    result = await middleware.on_call_tool(
        context,
        call_next,
    )

    assert result == 'result'

    fastmcp_context.elicit.assert_not_called()
    call_next.assert_awaited_once_with(context)

@pytest.mark.asyncio
async def test_missing_token_performs_device_authentication():
    provider = Mock()

    provider.ensure_access_token.side_effect = [
        ExpiredTokenError('Authentication required'),
        ExpiredTokenError('Authentication required'),
    ]

    provider.start_device_authorization.return_value = {
        'device_code': 'device-123',
        'user_code': 'ABCD-1234',
        'verification_uri': 'https://auth.example.com/verify',
        'expires_in': 600,
    }

    provider.complete_device_authorization.return_value = {
        'access_token': 'access-123',
    }

    middleware = OAuthDeviceAuthMiddleware(provider)

    fastmcp_context = Mock()

    fastmcp_context.elicit = AsyncMock(
        return_value=SimpleNamespace(
            action='accept',
            data=None,
        )
    )

    context = SimpleNamespace(
        fastmcp_context=fastmcp_context,
    )

    call_next = AsyncMock(return_value='tool-result')

    result = await middleware.on_call_tool(
        context,
        call_next,
    )

    assert result == 'tool-result'

    provider.start_device_authorization.assert_called_once()

    provider.complete_device_authorization.assert_called_once()

    fastmcp_context.elicit.assert_awaited_once()

    call_next.assert_awaited_once_with(context)

@pytest.mark.asyncio
async def test_user_can_cancel_device_authentication():
    provider = Mock()

    provider.ensure_access_token.side_effect = (
        ExpiredTokenError('Authentication required')
    )

    provider.start_device_authorization.return_value = {
        'device_code': 'device-123',
        'user_code': 'ABCD-1234',
        'verification_uri': 'https://auth.example.com/verify',
        'expires_in': 600,
    }

    middleware = OAuthDeviceAuthMiddleware(provider)

    fastmcp_context = Mock()

    fastmcp_context.elicit = AsyncMock(
        return_value=SimpleNamespace(
            action='decline',
            data=None,
        )
    )

    context = SimpleNamespace(
        fastmcp_context=fastmcp_context,
    )

    call_next = AsyncMock()

    with pytest.raises(ToolError):
        await middleware.on_call_tool(
            context,
            call_next,
        )

    provider.complete_device_authorization.assert_not_called()
    call_next.assert_not_called()