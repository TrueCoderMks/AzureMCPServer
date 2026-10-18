from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

import httpx
import pytest
from starlette.responses import JSONResponse

from entra_mcp_server.config import Settings
from entra_mcp_server.local_auth import (
    LocalEntraAuthMiddleware,
    LocalEntraSession,
    LocalSignInRequired,
)


class FakePublicClient:
    def __init__(self, *, client_id: str, authority: str) -> None:
        self.client_id = client_id
        self.authority = authority
        self.requested_scopes: list[str] | None = None

    def initiate_device_flow(self, *, scopes: list[str]) -> Mapping[str, Any]:
        self.requested_scopes = scopes
        return {"device_code": "device-code", "message": "Sign in at example.test"}

    def acquire_token_by_device_flow(self, flow: Mapping[str, Any]) -> Mapping[str, Any]:
        assert flow["device_code"] == "device-code"
        return {"access_token": "device-access-token"}

    def get_accounts(self) -> list[Mapping[str, Any]]:
        return [{"username": "user@example.test"}]

    def acquire_token_silent(
        self,
        scopes: list[str],
        *,
        account: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        assert scopes == self.requested_scopes
        assert account["username"] == "user@example.test"
        return {"access_token": "refreshed-access-token"}


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
        startup_auth=True,
        public_client_id="public-client-id",
        api_app_id_uri="api://api-id",
    )


def test_startup_sign_in_requests_read_scope_and_silently_refreshes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    clients: list[FakePublicClient] = []

    def factory(**kwargs: Any) -> FakePublicClient:
        client = FakePublicClient(**kwargs)
        clients.append(client)
        return client

    settings = make_settings()
    session = LocalEntraSession.sign_in(settings, public_client_factory=factory)

    assert clients[0].client_id == "public-client-id"
    assert clients[0].authority == f"https://login.microsoftonline.com/{settings.tenant_id}"
    assert clients[0].requested_scopes == ["api://api-id/Entra.Read"]
    assert "Sign in at example.test" in capsys.readouterr().err
    assert session.get_access_token() == "refreshed-access-token"


@pytest.mark.asyncio
async def test_local_middleware_injects_token_only_for_loopback_clients() -> None:
    async def downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
        authorization = next(
            (value.decode() for name, value in scope["headers"] if name == b"authorization"),
            None,
        )
        await JSONResponse({"authorization": authorization})(scope, receive, send)

    application = FakePublicClient(client_id="client", authority="authority")
    application.requested_scopes = ["api://api-id/Entra.Read"]
    session = LocalEntraSession(
        application,
        application.requested_scopes,
        {"username": "user@example.test"},
    )
    app = LocalEntraAuthMiddleware(downstream, session)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 50000)),
        base_url="http://127.0.0.1:8000",
    ) as client:
        local_response = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer untrusted-client-token"},
            json={},
        )

    assert local_response.status_code == 200
    assert local_response.json()["authorization"] == "Bearer refreshed-access-token"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.1", 50000)),
        base_url="http://127.0.0.1:8000",
    ) as client:
        remote_response = await client.post("/mcp", json={})

    assert remote_response.status_code == 403
    assert "loopback" in remote_response.json()["detail"]


def test_session_requires_interaction_when_silent_refresh_fails() -> None:
    class ExpiredPublicClient(FakePublicClient):
        def acquire_token_silent(
            self,
            scopes: list[str],
            *,
            account: Mapping[str, Any],
        ) -> None:
            return None

    application = ExpiredPublicClient(client_id="client", authority="authority")
    session = LocalEntraSession(
        application,
        ["api://api-id/Entra.Read"],
        {"username": "user@example.test"},
    )

    with pytest.raises(LocalSignInRequired, match="Restart the MCP server"):
        session.get_access_token()
