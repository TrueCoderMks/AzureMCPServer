from __future__ import annotations

import asyncio
import ipaddress
import logging
import sys
from collections.abc import Mapping
from typing import Any, Protocol

import msal
from starlette.responses import JSONResponse

from entra_mcp_server.config import Settings

logger = logging.getLogger(__name__)


class PublicClient(Protocol):
    def initiate_device_flow(self, *, scopes: list[str]) -> Mapping[str, Any]: ...

    def acquire_token_by_device_flow(self, flow: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def get_accounts(self) -> list[Mapping[str, Any]]: ...

    def acquire_token_silent(
        self,
        scopes: list[str],
        *,
        account: Mapping[str, Any],
    ) -> Mapping[str, Any] | None: ...


class LocalSignInRequired(RuntimeError):
    """Raised when the cached local Entra sign-in needs user interaction."""


class LocalEntraSession:
    def __init__(
        self,
        application: PublicClient,
        scopes: list[str],
        account: Mapping[str, Any],
    ) -> None:
        self._application = application
        self._scopes = scopes
        self._account = account

    @classmethod
    def sign_in(
        cls,
        settings: Settings,
        *,
        public_client_factory: Any = msal.PublicClientApplication,
        write_scopes: bool = False,
    ) -> LocalEntraSession:
        scope_names = ["Entra.Read"]
        if write_scopes:
            scope_names.append("Entra.Write")
        scopes = [f"{settings.api_app_id_uri}/{name}" for name in scope_names]
        application = public_client_factory(
            client_id=settings.public_client_id,
            authority=settings.graph_authority,
        )
        flow = application.initiate_device_flow(scopes=scopes)
        message = flow.get("message")
        if not isinstance(message, str) or not flow.get("device_code"):
            error = flow.get("error", "device_flow_initialization_failed")
            description = flow.get(
                "error_description", "No device authorization message was returned."
            )
            raise RuntimeError(f"{error}: {description}")

        print(message, file=sys.stderr, flush=True)
        result = application.acquire_token_by_device_flow(flow)
        if not isinstance(result.get("access_token"), str) or not result.get("access_token"):
            error = result.get("error", "token_acquisition_failed")
            description = result.get("error_description", "No access token was returned.")
            raise RuntimeError(f"{error}: {description}")

        accounts = application.get_accounts()
        if len(accounts) != 1:
            raise RuntimeError(
                "Could not identify the signed-in Entra account in the local token cache."
            )
        return cls(application, scopes, accounts[0])

    def get_access_token(self) -> str:
        result = self._application.acquire_token_silent(
            self._scopes,
            account=self._account,
        )
        access_token = result.get("access_token") if result else None
        if not isinstance(access_token, str) or not access_token:
            error = result.get("error", "interaction_required") if result else "interaction_required"
            logger.warning("Local Entra token refresh failed: %s", error)
            raise LocalSignInRequired(
                "The local Entra sign-in needs interaction. Restart the MCP server to sign in again."
            )
        return access_token


class LocalEntraAuthMiddleware:
    def __init__(self, app: Any, session: LocalEntraSession) -> None:
        self.app = app
        self.session = session

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") != "/mcp":
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        try:
            is_loopback = client is not None and ipaddress.ip_address(client[0]).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            await JSONResponse(
                {"detail": "Local startup authentication only permits loopback clients."},
                status_code=403,
            )(scope, receive, send)
            return

        try:
            token = await asyncio.to_thread(self.session.get_access_token)
        except LocalSignInRequired as exc:
            await JSONResponse({"detail": str(exc)}, status_code=503)(scope, receive, send)
            return

        headers = [
            (name, value)
            for name, value in scope.get("headers", [])
            if name.lower() != b"authorization"
        ]
        headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
        authenticated_scope = dict(scope)
        authenticated_scope["headers"] = headers
        await self.app(authenticated_scope, receive, send)
