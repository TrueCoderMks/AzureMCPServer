from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest

from entra_mcp_server.config import Settings
from entra_mcp_server.graph import (
    ConfidentialClient,
    EntraGraphClient,
    GraphAPIError,
    list_params,
    require_delete_confirmation,
)


def make_settings() -> Settings:
    return Settings(
        tenant_id=str(uuid4()),
        client_id=str(uuid4()),
        client_secret="test-only-secret",
        certificate_path=None,
        certificate_thumbprint=None,
        public_url="http://127.0.0.1:8000/mcp",
        host="127.0.0.1",
        port=8000,
        allowed_hosts=("127.0.0.1:*",),
        allowed_origins=(),
    )


class EmptyConfidentialClient:
    def acquire_token_on_behalf_of(
        self,
        *,
        user_assertion: str,
        scopes: list[str],
    ) -> dict[str, Any]:
        raise AssertionError("The test client overrides OBO token acquisition.")


class StubGraphClient(EntraGraphClient):
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport,
    ) -> None:
        self.requested_scopes: list[str] = []
        application: ConfidentialClient = EmptyConfidentialClient()
        super().__init__(settings, transport=transport, application=application)

    async def _acquire_token(self, user_assertion: str, scope: str) -> str:
        assert user_assertion == "incoming-user-token"
        self.requested_scopes.append(scope)
        return "outgoing-graph-token"


@pytest.mark.asyncio
async def test_graph_request_uses_fixed_graph_host_and_obo_token() -> None:
    received: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received["url"] = str(request.url)
        received["authorization"] = request.headers["Authorization"]
        return httpx.Response(200, json={"value": [{"id": "user-id"}]})

    client = StubGraphClient(make_settings(), transport=httpx.MockTransport(handler))
    result = await client.request(
        user_assertion="incoming-user-token",
        scope_key="users.read",
        method="GET",
        path="/users",
        params={"$top": 10},
    )

    assert received["url"] == "https://graph.microsoft.com/v1.0/users?%24top=10"
    assert received["authorization"] == "Bearer outgoing-graph-token"
    assert result == {"value": [{"id": "user-id"}]}
    assert client.requested_scopes == ["https://graph.microsoft.com/User.Read.All"]


@pytest.mark.asyncio
async def test_graph_write_uses_delegated_write_permission_and_payload() -> None:
    received: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        received["method"] = request.method
        received["url"] = str(request.url)
        received["body"] = request.read().decode()
        return httpx.Response(201, json={"id": "new-user"})

    client = StubGraphClient(make_settings(), transport=httpx.MockTransport(handler))
    result = await client.request(
        user_assertion="incoming-user-token",
        scope_key="users.write",
        method="POST",
        path="/users",
        body={"displayName": "Example User"},
    )

    assert received["method"] == "POST"
    assert received["url"] == "https://graph.microsoft.com/v1.0/users"
    assert received["body"] == '{"displayName":"Example User"}'
    assert client.requested_scopes == ["https://graph.microsoft.com/User.ReadWrite.All"]
    assert result == {"id": "new-user"}


@pytest.mark.asyncio
async def test_graph_response_redacts_password_fields() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json={
                "id": "user-id",
                "passwordProfile": {"password": "not-returned"},
                "credentials": [{"secretText": "not-returned"}],
            },
        )

    client = StubGraphClient(make_settings(), transport=httpx.MockTransport(handler))
    result = await client.request(
        user_assertion="incoming-user-token",
        scope_key="users.read",
        method="GET",
        path="/users",
    )

    assert result["passwordProfile"] == "[REDACTED]"
    assert result["credentials"][0]["secretText"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_graph_error_is_reported_without_silent_fallback() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"error": {"code": "Authorization_RequestDenied", "message": "Denied."}},
        )

    client = StubGraphClient(make_settings(), transport=httpx.MockTransport(handler))

    with pytest.raises(GraphAPIError, match="HTTP 403"):
        await client.request(
            user_assertion="incoming-user-token",
            scope_key="users.read",
            method="GET",
            path="/users",
        )


def test_delete_requires_explicit_confirmation_and_valid_uuid() -> None:
    object_id = str(uuid4())
    with pytest.raises(ValueError, match="confirm=true"):
        require_delete_confirmation(object_id, False)
    assert require_delete_confirmation(object_id, True) == object_id
    with pytest.raises(ValueError, match="valid Entra object UUID"):
        require_delete_confirmation("not-an-id", True)


def test_list_params_bounds_page_size() -> None:
    assert list_params(top=5, select="id,displayName", filter_expression=None) == {
        "$top": 5,
        "$select": "id,displayName",
    }
    with pytest.raises(ValueError, match="between 1 and 999"):
        list_params(top=1000, select=None, filter_expression=None)
