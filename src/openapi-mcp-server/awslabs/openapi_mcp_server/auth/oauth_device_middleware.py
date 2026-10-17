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

"""MCP middleware for interactive OAuth Device Authorization."""

import asyncio

from awslabs.openapi_mcp_server.auth.auth_errors import ExpiredTokenError
from awslabs.openapi_mcp_server.auth.oauth_device_auth import (
    OAuthDeviceAuthProvider,
)
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext


class OAuthDeviceAuthMiddleware(Middleware):
    """Ensure OAuth Device authentication before executing API tools."""

    def __init__(self, provider: OAuthDeviceAuthProvider):
        self._provider = provider
        self._authentication_lock = asyncio.Lock()

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next,
    ):
        """Authenticate the user before executing a tool."""

        try:
            await asyncio.to_thread(
                self._provider.ensure_access_token
            )

        except ExpiredTokenError:
            await self._authenticate_interactively(context)

        return await call_next(context)

    async def _authenticate_interactively(
        self,
        context: MiddlewareContext,
    ) -> None:
        """Perform an interactive OAuth Device Authorization flow."""

        async with self._authentication_lock:

            # Another request may have authenticated while this request
            # was waiting for the lock.
            try:
                await asyncio.to_thread(
                    self._provider.ensure_access_token
                )
                return

            except ExpiredTokenError:
                pass

            device_info = await asyncio.to_thread(
                self._provider.start_device_authorization
            )

            verification_uri = device_info['verification_uri']
            user_code = device_info['user_code']

            ctx = context.fastmcp_context

            if ctx is None:
                raise ToolError(
                    'OAuth Device authentication requires an '
                    'interactive MCP client'
                )

            message = (
                'Authentication is required.\n\n'
                f'Open: {verification_uri}\n\n'
                f'Enter code: {user_code}\n\n'
                'Complete the sign-in in your browser, then accept '
                'this prompt to continue.'
            )

            try:
                result = await ctx.elicit(
                    message=message,
                    response_type=None,
                )
            except Exception as e:
                raise ToolError(
                    'The MCP client does not support interactive '
                    'OAuth Device authentication'
                ) from e

            if result.action != 'accept':
                raise ToolError(
                    'OAuth Device authentication was cancelled'
                )

            await asyncio.to_thread(
                self._provider.complete_device_authorization
            )