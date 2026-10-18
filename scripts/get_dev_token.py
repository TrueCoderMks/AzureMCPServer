from __future__ import annotations

import os
import sys
from collections.abc import Callable, Mapping
from typing import Any, Protocol

import msal


class DeviceFlowClient(Protocol):
    def initiate_device_flow(self, *, scopes: list[str]) -> Mapping[str, Any]: ...

    def acquire_token_by_device_flow(self, flow: Mapping[str, Any]) -> Mapping[str, Any]: ...


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"Set {name} in this PowerShell session before running this script.")
    return value


def acquire_token(
    *,
    tenant_id: str,
    api_client_id: str,
    test_client_id: str,
    api_app_id_uri: str | None = None,
    scope_names: tuple[str, ...] = ("Entra.Read",),
    public_client_factory: Callable[..., DeviceFlowClient] = msal.PublicClientApplication,
) -> str:
    app_id_uri = (api_app_id_uri or f"api://{api_client_id}").rstrip("/")
    if not scope_names or any(name not in {"Entra.Read", "Entra.Write"} for name in scope_names):
        raise ValueError("scope_names must contain Entra.Read and optionally Entra.Write.")
    scopes = [f"{app_id_uri}/{name}" for name in dict.fromkeys(scope_names)]
    app = public_client_factory(
        client_id=test_client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )

    flow = app.initiate_device_flow(scopes=scopes)
    message = flow.get("message")
    if not isinstance(message, str) or not flow.get("device_code"):
        error = flow.get("error", "device_flow_initialization_failed")
        description = flow.get("error_description", "No device authorization message was returned.")
        raise RuntimeError(f"{error}: {description}")

    print(message, file=sys.stderr, flush=True)
    result = app.acquire_token_by_device_flow(flow)
    access_token = result.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        error = result.get("error", "token_acquisition_failed")
        description = result.get("error_description", "No access token was returned.")
        raise RuntimeError(f"{error}: {description}")
    return access_token


def main() -> None:
    try:
        access_token = acquire_token(
            tenant_id=required_env("ENTRA_TENANT_ID"),
            api_client_id=required_env("ENTRA_CLIENT_ID"),
            test_client_id=required_env("ENTRA_TEST_CLIENT_ID"),
            api_app_id_uri=os.getenv("ENTRA_API_APP_ID_URI") or None,
            scope_names=tuple(
                name
                for name in os.getenv("ENTRA_MCP_SCOPES", "Entra.Read").split()
                if name
            ),
        )
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc

    # PowerShell can pipe stdout directly into Set-Clipboard so the bearer token
    # is not printed into the terminal transcript.
    sys.stdout.write(access_token)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
