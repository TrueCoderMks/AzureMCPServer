from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest
from mcp import Client
from mcp.server.auth.provider import AccessToken

from entra_mcp_server.config import Settings
from entra_mcp_server.graph import EntraGraphClient
from entra_mcp_server.server import create_app, create_mcp_server


class EmptyConfidentialClient:
    def acquire_token_on_behalf_of(
        self,
        *,
        user_assertion: str,
        scopes: list[str],
    ) -> dict[str, Any]:
        raise AssertionError("No Graph call is expected in this test.")


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


def make_graph_client(settings: Settings) -> EntraGraphClient:
    return EntraGraphClient(settings, application=EmptyConfidentialClient())


@pytest.mark.asyncio
async def test_all_expected_tools_are_registered() -> None:
    settings = make_settings()
    server = create_mcp_server(settings, make_graph_client(settings))

    async with Client(server) as client:
        listing = await client.list_tools()

    names = {tool.name for tool in listing.tools}
    assert len(names) == 24
    assert {
        "whoami",
        "list_users",
        "create_user",
        "delete_user",
        "list_groups",
        "add_group_member",
        "remove_group_member",
        "list_applications",
        "delete_application",
        "list_service_principals",
        "delete_service_principal",
    } <= names


@pytest.mark.asyncio
async def test_whoami_returns_identity_without_exposing_access_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = make_settings()
    server = create_mcp_server(settings, make_graph_client(settings))
    access_token = AccessToken(
        token="never-return-this",
        client_id="vscode-test-client",
        scopes=["Entra.Read"],
        subject="user-object-id",
    )
    monkeypatch.setattr(
        "entra_mcp_server.server.get_access_token",
        lambda: access_token,
    )

    async with Client(server) as client:
        result = await client.call_tool("whoami", {})

    assert result.structured_content == {
        "subject": "user-object-id",
        "client_id": "vscode-test-client",
        "scopes": ["Entra.Read"],
    }
    assert "never-return-this" not in str(result)


@pytest.mark.asyncio
async def test_http_endpoint_requires_token_and_publishes_resource_metadata() -> None:
    settings = make_settings()
    app = create_app(settings, make_graph_client(settings))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8000",
        ) as client:
            unauthorized = await client.post("/mcp", json={})
            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")

    assert unauthorized.status_code == 401
    assert "resource_metadata=" in unauthorized.headers["www-authenticate"]
    assert metadata.status_code == 200
    assert settings.issuer in metadata.json()["authorization_servers"]
    assert "Entra.Read" in metadata.json()["scopes_supported"]
