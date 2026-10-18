from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp.server.auth.provider import AccessToken

from entra_mcp_server.auth import (
    MCP_READ_SCOPE,
    MCP_WRITE_SCOPE,
    EntraTokenVerifier,
    require_mcp_scope,
)
from entra_mcp_server.config import Settings


class StaticSigningKey:
    def __init__(self, key: Any) -> None:
        self.key = key


class StaticSigningKeyProvider:
    def __init__(self, key: Any) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> StaticSigningKey:
        return StaticSigningKey(self._key)


@pytest.fixture
def token_context() -> tuple[Settings, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tenant_id = str(uuid4())
    client_id = str(uuid4())
    settings = Settings(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret="test-only-secret",
        certificate_path=None,
        certificate_thumbprint=None,
        public_url="http://127.0.0.1:8000/mcp",
        host="127.0.0.1",
        port=8000,
        allowed_hosts=("127.0.0.1:*",),
        allowed_origins=(),
    )
    return settings, private_key


def make_token(
    settings: Settings,
    private_key: Any,
    *,
    overrides: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "aud": settings.client_id,
        "iss": settings.issuer,
        "tid": settings.tenant_id,
        "ver": "2.0",
        "oid": str(uuid4()),
        "sub": str(uuid4()),
        "azp": str(uuid4()),
        "scp": "Entra.Read Entra.Write",
        "iat": now,
        "nbf": now - timedelta(seconds=1),
        "exp": now + timedelta(minutes=5),
    }
    claims.update(overrides or {})
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


@pytest.mark.asyncio
async def test_verifier_accepts_valid_single_tenant_delegated_token(
    token_context: tuple[Settings, Any],
) -> None:
    settings, private_key = token_context
    verifier = EntraTokenVerifier(settings, StaticSigningKeyProvider(private_key.public_key()))

    result = await verifier.verify_token(make_token(settings, private_key))

    assert result is not None
    assert result.client_id
    assert result.subject
    assert set(result.scopes) == {"Entra.Read", "Entra.Write"}
    assert result.resource == settings.client_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claim_overrides",
    [
        {"aud": str(uuid4())},
        {"iss": "https://login.microsoftonline.com/common/v2.0"},
        {"tid": str(uuid4())},
        {"ver": "1.0"},
        {"scp": ""},
        {"scp": None},
        {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
    ],
)
async def test_verifier_rejects_wrong_or_non_delegated_tokens(
    token_context: tuple[Settings, Any],
    claim_overrides: dict[str, Any],
) -> None:
    settings, private_key = token_context
    verifier = EntraTokenVerifier(settings, StaticSigningKeyProvider(private_key.public_key()))

    result = await verifier.verify_token(
        make_token(settings, private_key, overrides=claim_overrides)
    )

    assert result is None


def test_mcp_tool_scope_enforcement() -> None:
    read_token = AccessToken(
        token="read-token",
        client_id="client",
        scopes=[MCP_READ_SCOPE],
    )
    write_token = AccessToken(
        token="write-token",
        client_id="client",
        scopes=[MCP_READ_SCOPE, MCP_WRITE_SCOPE],
    )

    assert require_mcp_scope(read_token, MCP_READ_SCOPE) == "read-token"
    assert require_mcp_scope(write_token, MCP_WRITE_SCOPE) == "write-token"
    with pytest.raises(PermissionError, match="Entra.Write"):
        require_mcp_scope(read_token, MCP_WRITE_SCOPE)
    with pytest.raises(PermissionError, match="authenticated"):
        require_mcp_scope(None, MCP_READ_SCOPE)
