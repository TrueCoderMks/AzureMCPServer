from __future__ import annotations

from typing import Any

from scripts.get_dev_token import acquire_token


class FakePublicClient:
    def __init__(self, *, client_id: str, authority: str) -> None:
        self.client_id = client_id
        self.authority = authority
        self.requested_scopes: list[str] | None = None

    def initiate_device_flow(self, *, scopes: list[str]) -> dict[str, str]:
        self.requested_scopes = scopes
        return {"device_code": "device-code", "message": "Sign in at example.test"}

    def acquire_token_by_device_flow(self, flow: dict[str, str]) -> dict[str, str]:
        assert flow["device_code"] == "device-code"
        return {"access_token": "short-lived-access-token"}


def test_device_token_requests_configured_api_scope(capsys: Any) -> None:
    clients: list[FakePublicClient] = []

    def factory(**kwargs: Any) -> FakePublicClient:
        client = FakePublicClient(**kwargs)
        clients.append(client)
        return client

    token = acquire_token(
        tenant_id="tenant-guid",
        api_client_id="api-client-guid",
        test_client_id="public-client-guid",
        api_app_id_uri="api://custom-api-uri",
        public_client_factory=factory,
    )

    assert token == "short-lived-access-token"
    assert clients[0].authority == "https://login.microsoftonline.com/tenant-guid"
    assert clients[0].client_id == "public-client-guid"
    assert clients[0].requested_scopes == ["api://custom-api-uri/Entra.Read"]
    assert "Sign in at example.test" in capsys.readouterr().err


def test_device_token_can_request_read_and_write_scopes() -> None:
    clients: list[FakePublicClient] = []

    def factory(**kwargs: Any) -> FakePublicClient:
        client = FakePublicClient(**kwargs)
        clients.append(client)
        return client

    acquire_token(
        tenant_id="tenant-guid",
        api_client_id="api-client-guid",
        test_client_id="public-client-guid",
        scope_names=("Entra.Read", "Entra.Write"),
        public_client_factory=factory,
    )

    assert clients[0].requested_scopes == [
        "api://api-client-guid/Entra.Read",
        "api://api-client-guid/Entra.Write",
    ]
