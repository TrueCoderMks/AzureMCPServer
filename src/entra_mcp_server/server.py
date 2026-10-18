from __future__ import annotations

from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl, Field
from starlette.applications import Starlette

from entra_mcp_server.auth import (
    MCP_READ_SCOPE,
    MCP_WRITE_SCOPE,
    EntraTokenVerifier,
    require_mcp_scope,
)
from entra_mcp_server.config import Settings
from entra_mcp_server.graph import (
    GRAPH_ROOT,
    EntraGraphClient,
    _object_path,
    list_params,
    require_delete_confirmation,
)
from entra_mcp_server.local_auth import LocalEntraAuthMiddleware, LocalEntraSession


def create_mcp_server(
    settings: Settings,
    graph_client: EntraGraphClient | None = None,
) -> MCPServer:
    graph = graph_client or EntraGraphClient(settings)
    server = MCPServer(
        "Microsoft Entra ID",
        token_verifier=EntraTokenVerifier(settings),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(settings.issuer),
            resource_server_url=AnyHttpUrl(settings.public_url),
            required_scopes=[MCP_READ_SCOPE],
            validate_token_resource=False,
        ),
    )

    def caller_token(required_scope: str) -> str:
        return require_mcp_scope(get_access_token(), required_scope)

    @server.tool()
    def whoami() -> dict[str, Any]:
        """Show the authenticated caller's object ID, client ID, and MCP scopes."""
        access_token = get_access_token()
        if access_token is None:
            raise PermissionError("An authenticated Entra user is required.")
        return {
            "subject": access_token.subject,
            "client_id": access_token.client_id,
            "scopes": access_token.scopes,
        }

    @server.tool()
    async def list_users(
        top: Annotated[int, Field(ge=1, le=999)] = 50,
        select: str | None = None,
        filter_expression: str | None = None,
    ) -> dict[str, Any]:
        """Read users from Microsoft Entra ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="users.read",
            method="GET",
            path=_object_path("users"),
            params=list_params(top=top, select=select, filter_expression=filter_expression),
        )

    @server.tool()
    async def get_user(user_id: str) -> dict[str, Any]:
        """Read one user by Entra object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="users.read",
            method="GET",
            path=_object_path("users", user_id),
        )

    @server.tool()
    async def create_user(user: dict[str, Any]) -> dict[str, Any]:
        """Create a user. Supply the Microsoft Graph user properties in user."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="users.write",
            method="POST",
            path=_object_path("users"),
            body=user,
        )

    @server.tool()
    async def update_user(user_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Update a user by Entra object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="users.write",
            method="PATCH",
            path=_object_path("users", user_id),
            body=user,
        )

    @server.tool()
    async def delete_user(user_id: str, confirm: bool) -> dict[str, Any]:
        """Delete one user; confirm must be true for the exact user_id."""
        object_id = require_delete_confirmation(user_id, confirm)
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="users.write",
            method="DELETE",
            path=_object_path("users", object_id),
        )

    @server.tool()
    async def list_groups(
        top: Annotated[int, Field(ge=1, le=999)] = 50,
        select: str | None = None,
        filter_expression: str | None = None,
    ) -> dict[str, Any]:
        """Read groups from Microsoft Entra ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="groups.read",
            method="GET",
            path=_object_path("groups"),
            params=list_params(top=top, select=select, filter_expression=filter_expression),
        )

    @server.tool()
    async def get_group(group_id: str) -> dict[str, Any]:
        """Read one group by Entra object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="groups.read",
            method="GET",
            path=_object_path("groups", group_id),
        )

    @server.tool()
    async def create_group(group: dict[str, Any]) -> dict[str, Any]:
        """Create a group. Supply the Microsoft Graph group properties in group."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="groups.write",
            method="POST",
            path=_object_path("groups"),
            body=group,
        )

    @server.tool()
    async def update_group(group_id: str, group: dict[str, Any]) -> dict[str, Any]:
        """Update a group by Entra object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="groups.write",
            method="PATCH",
            path=_object_path("groups", group_id),
            body=group,
        )

    @server.tool()
    async def delete_group(group_id: str, confirm: bool) -> dict[str, Any]:
        """Delete one group; confirm must be true for the exact group_id."""
        object_id = require_delete_confirmation(group_id, confirm)
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="groups.write",
            method="DELETE",
            path=_object_path("groups", object_id),
        )

    @server.tool()
    async def list_group_members(
        group_id: str,
        top: Annotated[int, Field(ge=1, le=999)] = 50,
    ) -> dict[str, Any]:
        """Read the members of a group."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="members.read",
            method="GET",
            path=f"{_object_path('groups', group_id)}/members",
            params={"$top": top},
        )

    @server.tool()
    async def add_group_member(group_id: str, member_id: str) -> dict[str, Any]:
        """Add one directory object to a group."""
        group_object_id = _object_path("groups", group_id).rsplit("/", 1)[1]
        member_object_id = _object_path("users", member_id).rsplit("/", 1)[1]
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="members.write",
            method="POST",
            path=f"/groups/{group_object_id}/members/$ref",
            body={"@odata.id": f"{GRAPH_ROOT}/directoryObjects/{member_object_id}"},
        )

    @server.tool()
    async def remove_group_member(
        group_id: str,
        member_id: str,
        confirm: bool,
    ) -> dict[str, Any]:
        """Remove one member from a group; confirm must be true for the exact IDs."""
        group_object_id = require_delete_confirmation(group_id, confirm)
        member_object_id = _object_path("users", member_id).rsplit("/", 1)[1]
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="members.write",
            method="DELETE",
            path=f"/groups/{group_object_id}/members/{member_object_id}/$ref",
        )

    @server.tool()
    async def list_applications(
        top: Annotated[int, Field(ge=1, le=999)] = 50,
        select: str | None = None,
        filter_expression: str | None = None,
    ) -> dict[str, Any]:
        """Read app registrations from Microsoft Entra ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="applications.read",
            method="GET",
            path=_object_path("applications"),
            params=list_params(top=top, select=select, filter_expression=filter_expression),
        )

    @server.tool()
    async def get_application(application_id: str) -> dict[str, Any]:
        """Read one app registration by object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="applications.read",
            method="GET",
            path=_object_path("applications", application_id),
        )

    @server.tool()
    async def create_application(application: dict[str, Any]) -> dict[str, Any]:
        """Create an app registration. Supply Microsoft Graph application properties."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="applications.write",
            method="POST",
            path=_object_path("applications"),
            body=application,
        )

    @server.tool()
    async def update_application(
        application_id: str,
        application: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an app registration by object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="applications.write",
            method="PATCH",
            path=_object_path("applications", application_id),
            body=application,
        )

    @server.tool()
    async def delete_application(application_id: str, confirm: bool) -> dict[str, Any]:
        """Delete one app registration; confirm must be true for the exact object ID."""
        object_id = require_delete_confirmation(application_id, confirm)
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="applications.write",
            method="DELETE",
            path=_object_path("applications", object_id),
        )

    @server.tool()
    async def list_service_principals(
        top: Annotated[int, Field(ge=1, le=999)] = 50,
        select: str | None = None,
        filter_expression: str | None = None,
    ) -> dict[str, Any]:
        """Read service principals from Microsoft Entra ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="applications.read",
            method="GET",
            path=_object_path("servicePrincipals"),
            params=list_params(top=top, select=select, filter_expression=filter_expression),
        )

    @server.tool()
    async def get_service_principal(service_principal_id: str) -> dict[str, Any]:
        """Read one service principal by object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_READ_SCOPE),
            scope_key="applications.read",
            method="GET",
            path=_object_path("servicePrincipals", service_principal_id),
        )

    @server.tool()
    async def create_service_principal(service_principal: dict[str, Any]) -> dict[str, Any]:
        """Create a service principal. Supply Microsoft Graph properties."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="applications.write",
            method="POST",
            path=_object_path("servicePrincipals"),
            body=service_principal,
        )

    @server.tool()
    async def update_service_principal(
        service_principal_id: str,
        service_principal: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a service principal by object ID."""
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="applications.write",
            method="PATCH",
            path=_object_path("servicePrincipals", service_principal_id),
            body=service_principal,
        )

    @server.tool()
    async def delete_service_principal(
        service_principal_id: str,
        confirm: bool,
    ) -> dict[str, Any]:
        """Delete one service principal; confirm must be true for the exact object ID."""
        object_id = require_delete_confirmation(service_principal_id, confirm)
        return await graph.request(
            user_assertion=caller_token(MCP_WRITE_SCOPE),
            scope_key="applications.write",
            method="DELETE",
            path=_object_path("servicePrincipals", object_id),
        )

    return server


def create_app(
    settings: Settings,
    graph_client: EntraGraphClient | None = None,
    *,
    local_session: LocalEntraSession | None = None,
) -> Starlette:
    if settings.startup_auth and local_session is None:
        raise ValueError("Startup authentication is enabled but no local Entra session was provided.")
    server = create_mcp_server(settings, graph_client)
    transport_security = TransportSecuritySettings(
        allowed_hosts=list(settings.allowed_hosts),
        allowed_origins=list(settings.allowed_origins),
    )
    app = server.streamable_http_app(transport_security=transport_security)
    if local_session is not None:
        app.add_middleware(LocalEntraAuthMiddleware, session=local_session)
    return app
