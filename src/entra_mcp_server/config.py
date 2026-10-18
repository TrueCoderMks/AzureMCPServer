from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID


class ConfigurationError(ValueError):
    """Raised when required server configuration is missing or unsafe."""


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigurationError(f"Required environment variable {name} is not set.")
    return value


def _validate_uuid(name: str, value: str) -> str:
    try:
        UUID(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a UUID.") from exc
    return value


@dataclass(frozen=True)
class Settings:
    tenant_id: str
    client_id: str
    client_secret: str | None
    certificate_path: Path | None
    certificate_thumbprint: str | None
    public_url: str
    host: str
    port: int
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    startup_auth: bool = False
    public_client_id: str | None = None
    api_app_id_uri: str | None = None

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/discovery/v2.0/keys"

    @property
    def graph_authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @classmethod
    def from_env(cls) -> Settings:
        tenant_id = _validate_uuid("ENTRA_TENANT_ID", _required_env("ENTRA_TENANT_ID"))
        client_id = _validate_uuid("ENTRA_CLIENT_ID", _required_env("ENTRA_CLIENT_ID"))
        host = os.getenv("MCP_HOST", "127.0.0.1").strip()
        startup_auth_value = os.getenv("MCP_STARTUP_AUTH", "").strip().lower()
        if startup_auth_value and startup_auth_value not in {"true", "false"}:
            raise ConfigurationError("MCP_STARTUP_AUTH must be true or false.")
        try:
            default_startup_auth = (
                host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
            )
        except ValueError:
            default_startup_auth = False
        use_startup_auth = (
            startup_auth_value == "true"
            if startup_auth_value
            else default_startup_auth
        )

        client_secret = os.getenv("MSAL_CLIENT_SECRET", "").strip() or None
        certificate_path_value = os.getenv("MSAL_CERTIFICATE_PATH", "").strip()
        certificate_thumbprint = os.getenv("MSAL_CERTIFICATE_THUMBPRINT", "").strip() or None
        certificate_path = Path(certificate_path_value) if certificate_path_value else None

        has_secret = client_secret is not None
        has_certificate = certificate_path is not None or certificate_thumbprint is not None
        if has_secret == has_certificate:
            raise ConfigurationError(
                "Configure exactly one server credential: MSAL_CLIENT_SECRET or both "
                "MSAL_CERTIFICATE_PATH and MSAL_CERTIFICATE_THUMBPRINT."
            )
        if has_certificate and (certificate_path is None or certificate_thumbprint is None):
            raise ConfigurationError(
                "MSAL_CERTIFICATE_PATH and MSAL_CERTIFICATE_THUMBPRINT must be configured together."
            )
        if certificate_path is not None and not certificate_path.is_file():
            raise ConfigurationError("The configured MSAL certificate file does not exist.")

        public_url = os.getenv("MCP_PUBLIC_URL", "http://127.0.0.1:8000/mcp").strip()
        parsed_url = urlsplit(public_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ConfigurationError("MCP_PUBLIC_URL must be an absolute HTTP(S) URL.")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed_url.hostname.lower() not in local_hosts and parsed_url.scheme != "https":
            raise ConfigurationError("MCP_PUBLIC_URL must use HTTPS outside localhost.")
        if parsed_url.path.rstrip("/") != "/mcp" or parsed_url.query or parsed_url.fragment:
            raise ConfigurationError("MCP_PUBLIC_URL must identify the /mcp endpoint without query or fragment.")

        if use_startup_auth:
            try:
                host_is_loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                host_is_loopback = False
            if not host_is_loopback or parsed_url.hostname.lower() not in local_hosts:
                raise ConfigurationError(
                    "MCP_STARTUP_AUTH requires MCP_HOST and MCP_PUBLIC_URL to use loopback addresses."
                )

        try:
            port = int(os.getenv("MCP_PORT", "8000"))
        except ValueError as exc:
            raise ConfigurationError("MCP_PORT must be an integer between 1 and 65535.") from exc
        if not 1 <= port <= 65535:
            raise ConfigurationError("MCP_PORT must be an integer between 1 and 65535.")

        allowed_hosts = tuple(
            entry.strip()
            for entry in os.getenv(
                "MCP_ALLOWED_HOSTS", "127.0.0.1:*,localhost:*,[::1]:*"
            ).split(",")
            if entry.strip()
        )
        if not allowed_hosts:
            raise ConfigurationError("MCP_ALLOWED_HOSTS must contain at least one allowed host.")

        allowed_origins = tuple(
            entry.strip()
            for entry in os.getenv("MCP_ALLOWED_ORIGINS", "").split(",")
            if entry.strip()
        )

        return cls(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            certificate_path=certificate_path,
            certificate_thumbprint=certificate_thumbprint,
            public_url=public_url.rstrip("/"),
            host=host,
            port=port,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            startup_auth=use_startup_auth,
            public_client_id=(
                _validate_uuid("ENTRA_TEST_CLIENT_ID", os.getenv("ENTRA_TEST_CLIENT_ID", "").strip())
                if os.getenv("ENTRA_TEST_CLIENT_ID", "").strip()
                else client_id
            ),
            api_app_id_uri=os.getenv("ENTRA_API_APP_ID_URI", "").strip() or f"api://{client_id}",
        )

    def msal_credential(self) -> str | dict[str, str]:
        if self.client_secret is not None:
            return self.client_secret
        if self.certificate_path is None or self.certificate_thumbprint is None:
            raise ConfigurationError("A client secret or certificate credential is required.")
        try:
            private_key = self.certificate_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError("Unable to read the configured certificate private key.") from exc
        return {
            "private_key": private_key,
            "thumbprint": self.certificate_thumbprint,
        }
