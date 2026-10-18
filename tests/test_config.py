from __future__ import annotations

from uuid import uuid4

import pytest

from entra_mcp_server.config import ConfigurationError, Settings


def set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENTRA_TENANT_ID", str(uuid4()))
    monkeypatch.setenv("ENTRA_CLIENT_ID", str(uuid4()))
    monkeypatch.setenv("MSAL_CLIENT_SECRET", "test-only-secret")
    monkeypatch.delenv("MSAL_CERTIFICATE_PATH", raising=False)
    monkeypatch.delenv("MSAL_CERTIFICATE_THUMBPRINT", raising=False)


def test_settings_accepts_local_http_and_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    set_required_env(monkeypatch)

    settings = Settings.from_env()

    assert settings.public_url == "http://127.0.0.1:8000/mcp"
    assert settings.issuer.endswith("/v2.0")
    assert settings.jwks_uri == (
        f"https://login.microsoftonline.com/{settings.tenant_id}/discovery/v2.0/keys"
    )
    assert settings.startup_auth is True
    assert settings.public_client_id == settings.client_id


def test_settings_can_disable_startup_auth_for_loopback_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_required_env(monkeypatch)
    monkeypatch.setenv("MCP_STARTUP_AUTH", "false")

    settings = Settings.from_env()

    assert settings.startup_auth is False


def test_startup_auth_cannot_bind_to_non_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    set_required_env(monkeypatch)
    monkeypatch.setenv("MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("MCP_STARTUP_AUTH", "true")

    with pytest.raises(ConfigurationError, match="loopback"):
        Settings.from_env()


def test_settings_rejects_nonlocal_http(monkeypatch: pytest.MonkeyPatch) -> None:
    set_required_env(monkeypatch)
    monkeypatch.setenv("MCP_PUBLIC_URL", "http://entra.example.com/mcp")

    with pytest.raises(ConfigurationError, match="must use HTTPS"):
        Settings.from_env()


def test_settings_requires_exactly_one_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    set_required_env(monkeypatch)
    monkeypatch.setenv("MSAL_CERTIFICATE_PATH", "certificate.pem")
    monkeypatch.setenv("MSAL_CERTIFICATE_THUMBPRINT", "thumbprint")

    with pytest.raises(ConfigurationError, match="exactly one server credential"):
        Settings.from_env()
