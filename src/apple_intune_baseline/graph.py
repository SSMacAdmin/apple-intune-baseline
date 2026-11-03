"""A small Microsoft Graph client for the Intune endpoints the MCP needs. Reads freely;
writes only through ``send``, which only push_policies calls."""

from __future__ import annotations

from typing import Any

import httpx

from .auth import GRAPH, GraphAuth
from .errors import UserInputError

BETA = f"{GRAPH}/beta"


class GraphError(UserInputError):
    """A Graph call failed in a way the person can act on."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class GraphClient:
    def __init__(
        self,
        auth: GraphAuth,
        tenant: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.auth = auth
        self.tenant = tenant
        self._http = httpx.Client(timeout=60, transport=transport)
        self._refreshed = False

    def _headers(self, fresh: bool = False) -> dict[str, str]:
        token = self.auth.get_token(self.tenant, force_refresh=True) if fresh else self.auth.get_token(self.tenant)
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    def get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        return self.request("GET", path, params=params)

    def send(self, method: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST/PUT/PATCH a JSON body. Only push_policies writes, after the person approved."""
        return self.request(method, path, body=body)

    def request(
        self, method: str, path: str, params: dict[str, str] | None = None, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        url = path if path.startswith("https://") else f"{BETA}{path}"

        def call(fresh: bool = False) -> httpx.Response:
            return self._http.request(method, url, params=params, json=body, headers=self._headers(fresh))

        resp = call()
        if resp.status_code == 403 and not self._refreshed:
            # The cached token may predate a permission consented since (e.g. after
            # re-running setup_app_registration). Get a fresh one once and retry.
            self._refreshed = True
            resp = call(fresh=True)
        if resp.status_code == 403:
            need = "ReadWrite.All" if method != "GET" else "Read.All (or ReadWrite.All)"
            raise GraphError(
                f"Graph returned 403 Forbidden. Check that the app registration has "
                f"DeviceManagementConfiguration.{need} with admin consent, and that your account "
                "has an Intune role that allows it.",
                403,
            )
        if resp.status_code == 401:
            raise GraphError("Graph returned 401. Call sign_out and then sign_in again.", 401)
        if resp.status_code >= 400:
            try:
                err = resp.json().get("error", {})
                msg = err.get("message", resp.text)
            except ValueError:
                msg = resp.text
            limit = 300 if method == "GET" else 1500
            raise GraphError(f"Graph error {resp.status_code} on {method} {path}: {msg[:limit]}", resp.status_code)
        if not resp.content:
            return {}
        return resp.json()

    def get_all(self, path: str, params: dict[str, str] | None = None, max_pages: int = 50) -> list[dict]:
        """Follow @odata.nextLink. Capped so a runaway query can't hang a tool call."""
        items: list[dict] = []
        page = self.get(path, params)
        for _ in range(max_pages):
            items.extend(page.get("value", []))
            nxt = page.get("@odata.nextLink")
            if not nxt:
                return items
            page = self.get(nxt)
        raise GraphError(f"Stopped after {max_pages} pages of {path}; narrow the query.")
