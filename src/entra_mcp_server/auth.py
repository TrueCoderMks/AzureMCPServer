from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError
from mcp.server.auth.provider import AccessToken, TokenVerifier

from entra_mcp_server.config import Settings

logger = logging.getLogger(__name__)
MCP_READ_SCOPE = "Entra.Read"
MCP_WRITE_SCOPE = "Entra.Write"


def require_mcp_scope(access_token: AccessToken | None, required_scope: str) -> str:
    if access_token is None:
        raise PermissionError("An authenticated Entra user is required.")
    if required_scope not in access_token.scopes:
        raise PermissionError(f"The {required_scope} MCP scope is required.")
    return access_token.token


class SigningKeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


class EntraTokenVerifier(TokenVerifier):
    """Validates delegated Microsoft Entra access tokens for this MCP API."""

    def __init__(
        self,
        settings: Settings,
        signing_key_provider: SigningKeyProvider | None = None,
    ) -> None:
        self._settings = settings
        self._signing_key_provider = signing_key_provider or PyJWKClient(
            settings.jwks_uri,
            cache_jwk_set=True,
            lifespan=3600,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = await asyncio.to_thread(
                self._signing_key_provider.get_signing_key_from_jwt, token
            )
        except PyJWKClientError as exc:
            logger.warning("Unable to retrieve an Entra signing key: %s", type(exc).__name__)
            return None

        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._settings.client_id,
                issuer=self._settings.issuer,
                leeway=60,
                options={
                    "require": ["aud", "exp", "iat", "iss", "sub", "tid"],
                },
            )
        except (jwt.PyJWTError, ValueError, TypeError):
            return None

        if claims.get("tid") != self._settings.tenant_id or claims.get("ver") != "2.0":
            return None

        delegated_scopes = claims.get("scp")
        if not isinstance(delegated_scopes, str) or not delegated_scopes.strip():
            return None
        scopes = delegated_scopes.split()
        if MCP_READ_SCOPE not in scopes:
            return None

        client_id = claims.get("azp")
        if not isinstance(client_id, str) or not client_id:
            return None

        subject = claims.get("oid") or claims.get("sub")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=self._settings.client_id,
            subject=str(subject),
            claims=claims,
        )
