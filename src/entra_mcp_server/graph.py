from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import quote
from uuid import UUID

import httpx
import msal

from entra_mcp_server.config import Settings

logger = logging.getLogger(__name__)
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"

GRAPH_SCOPES = {
    "users.read": "https://graph.microsoft.com/User.Read.All",
    "users.write": "https://graph.microsoft.com/User.ReadWrite.All",
    "groups.read": "https://graph.microsoft.com/Group.Read.All",
    "groups.write": "https://graph.microsoft.com/Group.ReadWrite.All",
    "members.read": "https://graph.microsoft.com/GroupMember.Read.All",
    "members.write": "https://graph.microsoft.com/GroupMember.ReadWrite.All",
    "applications.read": "https://graph.microsoft.com/Application.Read.All",
    "applications.write": "https://graph.microsoft.com/Application.ReadWrite.All",
}


class ConfidentialClient(Protocol):
    def acquire_token_on_behalf_of(
        self,
        *,
        user_assertion: str,
        scopes: list[str],
    ) -> dict[str, Any]: ...


_SENSITIVE_FIELDS = {
    "password",
    "passwordprofile",
    "passwordcredentials",
    "keycredentials",
    "privatekey",
    "secrettext",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
}


class GraphAPIError(RuntimeError):
    """A Microsoft Graph request failed."""


def _safe_response(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: "[REDACTED]" if key.casefold() in _SENSITIVE_FIELDS else _safe_response(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe_response(item) for item in value]
    return value


def _object_path(resource: str, object_id: str | None = None) -> str:
    if resource not in {"users", "groups", "applications", "servicePrincipals"}:
        raise ValueError("Unsupported directory resource.")
    if object_id is None:
        return f"/{resource}"
    try:
        encoded_id = quote(str(UUID(object_id)), safe="")
    except (ValueError, AttributeError) as exc:
        raise ValueError("object_id must be a valid Entra object UUID.") from exc
    return f"/{resource}/{encoded_id}"


class EntraGraphClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        application: ConfidentialClient | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._application = application or msal.ConfidentialClientApplication(
            client_id=settings.client_id,
            authority=settings.graph_authority,
            client_credential=settings.msal_credential(),
        )

    async def _acquire_token(self, user_assertion: str, scope: str) -> str:
        result = await asyncio.to_thread(
            self._application.acquire_token_on_behalf_of,
            user_assertion=user_assertion,
            scopes=[scope],
        )
        access_token = result.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            error_code = result.get("error", "token_acquisition_failed")
            logger.warning("Microsoft Graph delegated token acquisition failed: %s", error_code)
            raise GraphAPIError("Unable to acquire a delegated Microsoft Graph access token.")
        return access_token

    async def request(
        self,
        *,
        user_assertion: str,
        scope_key: str,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, str | int] | None = None,
    ) -> Any:
        try:
            scope = GRAPH_SCOPES[scope_key]
        except KeyError as exc:
            raise ValueError("Unsupported Microsoft Graph permission profile.") from exc

        graph_token = await self._acquire_token(user_assertion, scope)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=5.0),
            transport=self._transport,
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method,
                f"{GRAPH_ROOT}{path}",
                headers={"Authorization": f"Bearer {graph_token}"},
                json=body,
                params=params,
            )

        if not response.is_success:
            code = "unknown"
            message = "Microsoft Graph rejected the request."
            try:
                graph_error = response.json().get("error", {})
                code = str(graph_error.get("code", code))
                message = str(graph_error.get("message", message))
            except (ValueError, AttributeError):
                pass
            logger.warning("Microsoft Graph request failed with HTTP %s (%s).", response.status_code, code)
            raise GraphAPIError(f"Microsoft Graph returned HTTP {response.status_code}: {message}")

        if response.status_code == 204 or not response.content:
            return {"status": "success"}
        return _safe_response(response.json())


def list_params(
    *,
    top: int,
    select: str | None,
    filter_expression: str | None,
) -> dict[str, str | int]:
    if not 1 <= top <= 999:
        raise ValueError("top must be between 1 and 999.")
    if select is not None and len(select) > 2048:
        raise ValueError("select must be 2048 characters or fewer.")
    if filter_expression is not None and len(filter_expression) > 2048:
        raise ValueError("filter_expression must be 2048 characters or fewer.")
    params: dict[str, str | int] = {"$top": top}
    if select:
        params["$select"] = select
    if filter_expression:
        params["$filter"] = filter_expression
    return params


def require_delete_confirmation(object_id: str, confirm: bool) -> str:
    if not confirm:
        raise ValueError("Set confirm=true after verifying the exact object_id to delete.")
    try:
        return str(UUID(object_id))
    except ValueError as exc:
        raise ValueError("object_id must be a valid Entra object UUID.") from exc
