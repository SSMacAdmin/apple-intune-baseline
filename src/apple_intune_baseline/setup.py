"""Create this MCP's own Entra app registration from inside Claude.

Same flow as mac-packager: a one-time bootstrap sign-in with Microsoft Graph
PowerShell's public client (as Connect-MgGraph does) with just the scopes needed
to create an app and grant consent. The bootstrap tokens live in memory only and
are dropped afterwards; from then on the MCP signs in with its own,
least-privilege, single-tenant public client app. Re-running updates the app with
the same name instead of creating a duplicate.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import httpx

from .auth import GRAPH, MsalAuth, claims
from .errors import UserInputError
from .tenants import TenantStore

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# The "Default Access" app role, used to assign users when an app has no roles of its own.
DEFAULT_ACCESS_ROLE = "00000000-0000-0000-0000-000000000000"

PERMISSION_SETS: dict[str, list[str]] = {
    # GroupMember.Read.All only resolves assignment group names in the coverage check.
    # DeviceManagementScripts covers discovery and remediation scripts.
    # DeviceManagementManagedDevices.Read.All reads per-device results (device_results).
    "readOnly": ["User.Read", "DeviceManagementConfiguration.Read.All", "GroupMember.Read.All",
                 "DeviceManagementScripts.Read.All", "DeviceManagementManagedDevices.Read.All"],
    # Pushing Settings Catalog, custom and compliance policies, and scripts.
    "full": ["User.Read", "DeviceManagementConfiguration.ReadWrite.All", "GroupMember.Read.All",
             "DeviceManagementScripts.ReadWrite.All", "DeviceManagementManagedDevices.Read.All"],
}


def bootstrap_scopes(restrict_to_me: bool, grant_admin_consent: bool) -> list[str]:
    scopes = ["User.Read", "Application.ReadWrite.All"]
    if grant_admin_consent:
        scopes.append("DelegatedPermissionGrant.ReadWrite.All")
    if restrict_to_me:
        scopes.append("AppRoleAssignment.ReadWrite.All")
    return scopes


class _Graph:
    """Minimal v1.0 Graph caller for setup, using the bootstrap token directly."""

    def __init__(self, token: str, transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(
            base_url=f"{GRAPH}/v1.0",
            headers={"Authorization": f"Bearer {token}"},
            timeout=60,
            transport=transport,
        )

    def call(self, method: str, path: str, body: dict | None = None, params: dict | None = None) -> Any:
        resp = self._http.request(method, path, json=body, params=params)
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("error", {}).get("message", resp.text)
            except ValueError:
                msg = resp.text
            raise UserInputError(f"Graph {method} {path.split('?')[0]} failed ({resp.status_code}): {msg[:300]}")
        return resp.json() if resp.content else {}

    def all(self, path: str, params: dict | None = None) -> list[dict]:
        page = self.call("GET", path, params=params)
        items = list(page.get("value", []))
        while page.get("@odata.nextLink"):
            page = self.call("GET", page["@odata.nextLink"].split("/v1.0", 1)[1])
            items.extend(page.get("value", []))
        return items


def setup_app_registration(
    auth: MsalAuth,
    store: TenantStore,
    display_name: str,
    connection_name: str | None,
    permission_set: str,
    restrict_to_me: bool,
    grant_admin_consent: bool,
    *,
    bootstrap: Callable[[list[str]], dict | None] | None = None,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if permission_set not in PERMISSION_SETS:
        raise UserInputError("permission_set must be 'readOnly' or 'full'.")

    # 1. Bootstrap sign-in ("organizations": the account decides the tenant).
    sign_in = bootstrap or auth.bootstrap_token
    boot = sign_in(bootstrap_scopes(restrict_to_me, grant_admin_consent))
    if boot is None:
        return {
            "status": "pending",
            "message": (
                "A browser window opened for the one-time setup sign-in. Sign in as an admin who "
                "can create app registrations (and grant consent, if requested), then call "
                "setup_app_registration again with the same settings."
            ),
        }
    tenant_id = claims(boot.get("id_token")).get("tid") or boot.get("id_token_claims", {}).get("tid")
    if not tenant_id:
        raise UserInputError("Could not read the tenant ID from the setup sign-in.")
    g = _Graph(boot["access_token"], transport)

    try:
        me = g.call("GET", "/me", params={"$select": "id,userPrincipalName"})
        tenant_domain = None
        try:
            org = g.call("GET", "/organization", params={"$select": "verifiedDomains"})
            domains = org["value"][0]["verifiedDomains"]
            tenant_domain = next((d["name"] for d in domains if d.get("isDefault")), None)
        except (UserInputError, KeyError, IndexError):
            pass  # display only

        # 2. Resolve Graph's delegated scope IDs instead of hard-coding GUIDs.
        graph_sp = g.call(
            "GET",
            f"/servicePrincipals(appId='{GRAPH_APP_ID}')",
            params={"$select": "id,oauth2PermissionScopes"},
        )
        scopes = PERMISSION_SETS[permission_set]
        by_value = {s["value"]: s["id"] for s in graph_sp["oauth2PermissionScopes"]}
        missing = [s for s in scopes if s not in by_value]
        if missing:
            raise UserInputError(f"Graph scopes not found in this tenant: {missing}")
        app_body = {
            "displayName": display_name,
            "signInAudience": "AzureADMyOrg",
            "isFallbackPublicClient": True,
            "publicClient": {"redirectUris": ["http://localhost"]},
            "requiredResourceAccess": [
                {
                    "resourceAppId": GRAPH_APP_ID,
                    "resourceAccess": [{"id": by_value[s], "type": "Scope"} for s in scopes],
                }
            ],
            "notes": (
                f"Created by the apple-intune-baseline MCP for {me['userPrincipalName']}. "
                f"Delegated, public client (no secrets). Permission set: {permission_set}."
            ),
        }

        # 3. Create the app, or update the one with the same name so re-running is safe.
        safe_name = display_name.replace("'", "''")
        existing = g.all(
            "/applications", params={"$filter": f"displayName eq '{safe_name}'", "$select": "id,appId"}
        )
        if len(existing) > 1:
            raise UserInputError(f'More than one app registration is named "{display_name}". Use a unique name.')
        if existing:
            app, reused = existing[0], True
            g.call("PATCH", f"/applications/{app['id']}", app_body)
        else:
            app, reused = g.call("POST", "/applications", app_body), False

        # 4. Service principal (the Enterprise App). A brand-new app takes a moment to replicate.
        sp = None
        for attempt in range(6):
            found = g.all("/servicePrincipals", params={"$filter": f"appId eq '{app['appId']}'", "$select": "id"})
            if found:
                sp = found[0]
                break
            try:
                sp = g.call(
                    "POST",
                    "/servicePrincipals",
                    {"appId": app["appId"], "tags": ["WindowsAzureActiveDirectoryIntegratedApp"]},
                )
                break
            except UserInputError:
                if attempt == 5:
                    raise
                sleep(3)
        g.call("PATCH", f"/servicePrincipals/{sp['id']}", {"appRoleAssignmentRequired": restrict_to_me})

        # 5. Only the person who set it up may sign in (more users can be added in Enterprise apps).
        assigned_to = None
        if restrict_to_me:
            current = g.all(f"/servicePrincipals/{sp['id']}/appRoleAssignedTo")
            if not any(a.get("principalId") == me["id"] for a in current):
                g.call(
                    "POST",
                    f"/servicePrincipals/{sp['id']}/appRoleAssignedTo",
                    {"principalId": me["id"], "resourceId": sp["id"], "appRoleId": DEFAULT_ACCESS_ROLE},
                )
            assigned_to = me["userPrincipalName"]

        # 6. Tenant-wide admin consent for the delegated scopes.
        portal_url = (
            "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/"
            f"ApplicationMenuBlade/~/CallAnAPI/appId/{app['appId']}"
        )
        admin_consent: Any = "not_requested"
        if grant_admin_consent:
            try:
                grants = g.all(
                    "/oauth2PermissionGrants",
                    params={"$filter": f"clientId eq '{sp['id']}' and resourceId eq '{graph_sp['id']}'"},
                )
                org_grant = next((x for x in grants if x.get("consentType") == "AllPrincipals"), None)
                scope_string = " ".join(scopes)
                if org_grant:
                    g.call("PATCH", f"/oauth2PermissionGrants/{org_grant['id']}", {"scope": scope_string})
                else:
                    g.call(
                        "POST",
                        "/oauth2PermissionGrants",
                        {
                            "clientId": sp["id"],
                            "consentType": "AllPrincipals",
                            "resourceId": graph_sp["id"],
                            "scope": scope_string,
                        },
                    )
                admin_consent = "granted"
            except UserInputError as exc:
                admin_consent = {
                    "failed": str(exc),
                    "grant_in_portal": f"{portal_url} > Grant admin consent "
                    "(needs Global Administrator or Privileged Role Administrator)",
                }

        # 7. Save the connection locally (IDs only, no secrets).
        name = connection_name or tenant_domain or tenant_id
        if "." in name:  # tenant names are short labels; keep the domain separately
            name = name.split(".")[0]
        store.add(name, tenant_id, app["appId"], domain=tenant_domain, permission_set=permission_set)

        return {
            "status": "done",
            "reused_existing_app": reused,
            "tenant": name,
            "tenant_id": tenant_id,
            "tenant_domain": tenant_domain,
            "app_id": app["appId"],
            "object_id": app["id"],
            "service_principal_id": sp["id"],
            "permissions": scopes,
            "assigned_to": assigned_to,
            "admin_consent": admin_consent,
            "portal_url": portal_url,
            "next": "Call sign_in to sign in with the new app registration.",
        }
    finally:
        # The bootstrap tokens can create apps and grant consent; drop them now.
        auth.drop_bootstrap()
