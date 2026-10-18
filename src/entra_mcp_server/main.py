from __future__ import annotations

import os


def main() -> None:
    from entra_mcp_server.bootstrap import ensure_dependencies, load_environment

    ensure_dependencies()
    load_environment()

    import uvicorn

    from entra_mcp_server.config import Settings
    from entra_mcp_server.local_auth import LocalEntraSession
    from entra_mcp_server.server import create_app

    settings = Settings.from_env()
    local_session = None
    if settings.startup_auth:
        scopes = set(os.getenv("ENTRA_MCP_SCOPES", "Entra.Read").split())
        invalid_scopes = scopes - {"Entra.Read", "Entra.Write"}
        if not scopes or invalid_scopes or "Entra.Read" not in scopes:
            raise ValueError("ENTRA_MCP_SCOPES must include Entra.Read and may include Entra.Write.")
        local_session = LocalEntraSession.sign_in(
            settings,
            write_scopes="Entra.Write" in scopes,
        )
    app = create_app(settings, local_session=local_session)
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
