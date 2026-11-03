"""Microsoft Graph sign-in seam.

Locally the MCP signs in interactively in the browser with MSAL, using each
tenant's own app registration (created by ``setup_app_registration``), and
caches tokens in the macOS Keychain. A hosted mode would add another
:class:`GraphAuth` implementation (per-user OAuth) without the tools changing.

Sign-in never blocks a tool call for long: it waits briefly, then reports
"pending" while the browser sign-in carries on in the background; calling it
again picks up the result. Same pattern as mac-packager.

The MCP signs in to Graph itself. It never depends on another MCP server
(such as Lokka) at runtime.
"""

from __future__ import annotations

import base64
import json
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .errors import UserInputError
from .tenants import Tenant, TenantStore

GRAPH = "https://graph.microsoft.com"
# The MCP's own app registration holds exactly the permissions it needs, so
# ".default" asks for whatever was consented: read-only or full.
DEFAULT_SCOPES = [f"{GRAPH}/.default"]
# Microsoft Graph PowerShell's public client (what Connect-MgGraph uses). Only for
# the one-time setup sign-in; its tokens are never written to disk.
GRAPH_POWERSHELL_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SIGN_IN_WAIT_SECONDS = 45

_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font:16px -apple-system,system-ui,sans-serif;display:grid;place-items:center;height:100vh;
margin:0;background:#f5f5f7;color:#1d1d1f}}@media(prefers-color-scheme:dark){{body{{background:#1d1d1f;
color:#f5f5f7}}}}main{{text-align:center;max-width:28rem;padding:1rem}}</style></head>
<body><main><h1>{title}</h1><p>{body}</p></main></body></html>"""
SUCCESS_PAGE = _PAGE.format(
    title="Signed in", body="apple-intune-baseline is connected. You can close this tab and go back to Claude."
)
ERROR_PAGE = _PAGE.format(
    title="Sign-in failed", body="Something went wrong: $error. Go back to Claude for details."
)


class NotSignedInError(UserInputError):
    """A tool needs Graph and there is no usable token for the tenant."""


@runtime_checkable
class GraphAuth(Protocol):
    def get_token(self, tenant: str | None = None, force_refresh: bool = False) -> str:
        """A bearer token for Microsoft Graph, without user interaction. force_refresh skips
        the cached access token, e.g. to pick up permissions consented since it was issued."""
        ...

    def sign_in(self, tenant: str | None = None) -> dict:
        """Interactive sign-in. Returns status 'signed_in' or 'pending'."""
        ...

    def sign_out(self, tenant: str | None = None) -> dict: ...

    def status(self) -> dict:
        """User-facing sign-in state for the configured tenants."""
        ...


def claims(id_token: str | None) -> dict[str, Any]:
    """Read display claims from an ID token. Not a security check; MSAL validates."""
    if not id_token or id_token.count(".") != 2:
        return {}
    payload = id_token.split(".")[1]
    try:
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return {}


def explain_failure(result: dict, what: str) -> UserInputError:
    desc = result.get("error_description") or result.get("error") or "unknown error"
    hint = ""
    if "AADSTS65001" in desc or "consent" in desc.lower():
        hint = " Admin consent is missing: re-run setup_app_registration with admin consent, or grant it in Entra."
    elif "AADSTS50105" in desc:
        hint = " Your account isn't assigned to the app; add it under Enterprise apps > Users and groups."
    elif "AADSTS50011" in desc or "redirect" in desc.lower():
        hint = " The app needs http://localhost as a public client redirect URI."
    return UserInputError(f"{what} failed: {desc.splitlines()[0]}{hint}")


class _Interactive:
    """Runs interactive sign-ins in the background so tool calls return quickly."""

    def __init__(self) -> None:
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sign-in")
        self._pending: dict[str, Future] = {}
        self._lock = threading.Lock()

    def run(self, key: str, start, wait: float) -> dict | None:
        """Start (or join) the sign-in for ``key``; None means still pending."""
        with self._lock:
            fut = self._pending.get(key)
            if fut is None:
                fut = self._pool.submit(start)
                self._pending[key] = fut
        try:
            result = fut.result(timeout=wait)
        except TimeoutError:
            return None
        with self._lock:
            self._pending.pop(key, None)
        return result


class MsalAuth:
    """Interactive browser sign-in per tenant, tokens in the Keychain (file cache elsewhere)."""

    def __init__(self, store: TenantStore, cache_dir: Path, wait: float = SIGN_IN_WAIT_SECONDS) -> None:
        self.store = store
        self.cache_dir = cache_dir
        self.wait = wait
        self._apps: dict[str, Any] = {}
        self._token_cache = None
        self._interactive = _Interactive()
        self._bootstrap_app = None

    # --------------------------------------------------------------- plumbing

    def _cache(self):
        if self._token_cache is not None:
            return self._token_cache
        import msal_extensions as mx

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if sys.platform == "darwin":
            persistence = mx.KeychainPersistence(
                str(self.cache_dir / "token_cache.signal"),
                service_name="apple-intune-baseline",
                account_name="msal-token-cache",
            )
        else:  # tests and non-Mac development
            persistence = mx.FilePersistence(str(self.cache_dir / "token_cache.bin"))
        self._token_cache = mx.PersistedTokenCache(persistence)
        return self._token_cache

    def _signed_in_as(self, tenant: Tenant) -> str | None:
        """Who holds a refresh token for this tenant's app, read without network.

        Creating an MSAL app fetches the tenant's sign-in metadata, so status and
        "not signed in" checks read the cache directly instead.
        """
        import msal

        cache = self._cache()
        tokens = cache.search(
            msal.TokenCache.CredentialType.REFRESH_TOKEN, query={"client_id": tenant.client_id}
        )
        homes = {t.get("home_account_id", "") for t in tokens}
        if "." not in tenant.tenant_id:
            homes = {h for h in homes if h.lower().endswith("." + tenant.tenant_id.lower())}
        if not homes:
            return None
        for acct in cache.search(msal.TokenCache.CredentialType.ACCOUNT):
            if acct.get("home_account_id") in homes:
                return acct.get("username") or "signed in"
        return "signed in"

    def _app(self, tenant: Tenant):
        import msal

        key = f"{tenant.tenant_id}|{tenant.client_id}"
        if key not in self._apps:
            self._apps[key] = msal.PublicClientApplication(
                tenant.client_id, authority=tenant.authority, token_cache=self._cache()
            )
        return self._apps[key]

    def _browser_sign_in(self, app, scopes: list[str], key: str, login_hint: str | None = None) -> dict | None:
        def start() -> dict:
            return app.acquire_token_interactive(
                scopes,
                prompt="select_account",
                login_hint=login_hint,
                timeout=600,
                success_template=SUCCESS_PAGE,
                error_template=ERROR_PAGE,
            )

        return self._interactive.run(key, start, self.wait)

    # -------------------------------------------------------------------- api

    def get_token(self, tenant: str | None = None, force_refresh: bool = False) -> str:
        t = self.store.get(tenant)
        result = None
        if self._signed_in_as(t):
            app = self._app(t)
            accounts = app.get_accounts()
            result = (
                app.acquire_token_silent(DEFAULT_SCOPES, account=accounts[0], force_refresh=force_refresh)
                if accounts
                else None
            )
        if not result or "access_token" not in result:
            raise NotSignedInError(f"Not signed in to '{t.name}'. Call sign_in first; it opens a browser.")
        return result["access_token"]

    def sign_in(self, tenant: str | None = None) -> dict:
        t = self.store.get(tenant)
        app = self._app(t)
        if self._signed_in_as(t):
            accounts = app.get_accounts()
            silent = app.acquire_token_silent(DEFAULT_SCOPES, account=accounts[0]) if accounts else None
            if silent and "access_token" in silent:
                return {"tenant": t.name, "status": "signed_in", "account": accounts[0].get("username")}
        result = self._browser_sign_in(app, DEFAULT_SCOPES, f"tenant|{t.name}")
        if result is None:
            return {
                "tenant": t.name,
                "status": "pending",
                "message": "A browser window is open for sign-in. Finish it there, then call sign_in again.",
            }
        if "access_token" not in result:
            raise explain_failure(result, f"Sign-in to '{t.name}'")
        return {
            "tenant": t.name,
            "status": "signed_in",
            "account": claims(result.get("id_token")).get("preferred_username"),
            "scopes": result.get("scope", "").split(),
        }

    def bootstrap_token(self, scopes: list[str]) -> dict | None:
        """One-time setup sign-in with Graph PowerShell's client, in memory only.

        Returns MSAL's result, or None while the browser sign-in is pending.
        The tokens never touch the Keychain and are dropped with drop_bootstrap().
        """
        import msal

        if self._bootstrap_app is None:
            self._bootstrap_app = msal.PublicClientApplication(
                GRAPH_POWERSHELL_CLIENT_ID,
                authority="https://login.microsoftonline.com/organizations",
                token_cache=msal.TokenCache(),  # in memory, never persisted
            )
        full = [s if "://" in s else f"{GRAPH}/{s}" for s in scopes]
        result = self._browser_sign_in(self._bootstrap_app, full, "bootstrap|" + " ".join(sorted(full)))
        if result is not None and "access_token" not in result:
            raise explain_failure(result, "Setup sign-in")
        return result

    def drop_bootstrap(self) -> None:
        self._bootstrap_app = None

    def sign_out(self, tenant: str | None = None) -> dict:
        t = self.store.get(tenant)
        removed = 0
        if self._signed_in_as(t):
            app = self._app(t)
            for account in app.get_accounts():
                app.remove_account(account)
                removed += 1
        return {"tenant": t.name, "status": "signed_out", "accounts_removed": removed}

    def status(self) -> dict:
        return {
            "mode": "interactive (MSAL, per-tenant app registration)",
            "token_cache": "macOS Keychain" if sys.platform == "darwin" else "file",
            "tenants": [
                {
                    "name": t.name,
                    "tenant_id": t.tenant_id,
                    "domain": t.domain,
                    "permission_set": t.permission_set,
                    "active": t.name == self.store.active_name,
                    "signed_in_as": self._signed_in_as(t),
                }
                for t in self.store.list()
            ],
        }
