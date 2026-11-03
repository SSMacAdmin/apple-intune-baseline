"""Tenants the MCP can sign in to, each with its own app registration.

Stored as ``tenants.json`` in the workspace. It holds only identifiers
(tenant ID, client ID), never secrets or tokens; tokens live in the
sign-in provider's cache (the macOS Keychain locally).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import UserInputError

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_DOMAIN = re.compile(r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


@dataclass(frozen=True)
class Tenant:
    name: str
    tenant_id: str  # GUID or verified domain, e.g. contoso.onmicrosoft.com
    client_id: str  # Application (client) ID of this tenant's app registration
    domain: str | None = None  # default domain, for display
    permission_set: str = "readOnly"  # "readOnly" or "full", as created by setup

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"


class TenantStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    # ------------------------------------------------------------------ io

    def _read(self) -> dict:
        if not self.path.exists():
            return {"active": None, "tenants": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise UserInputError(f"Could not read {self.path}: {exc}") from exc
        data.setdefault("active", None)
        data.setdefault("tenants", {})
        return data

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    # ----------------------------------------------------------------- api

    def list(self) -> list[Tenant]:
        return [Tenant(name=n, **v) for n, v in sorted(self._read()["tenants"].items())]

    @property
    def active_name(self) -> str | None:
        return self._read()["active"]

    def get(self, name: str | None = None) -> Tenant:
        data = self._read()
        key = name or data["active"]
        if not key:
            raise UserInputError(
                "No tenant configured yet. Call setup_app_registration to create this "
                "MCP's app registration in your tenant (one-time)."
            )
        if key not in data["tenants"]:
            known = ", ".join(sorted(data["tenants"])) or "none"
            raise UserInputError(f"Unknown tenant '{key}'. Configured: {known}")
        return Tenant(name=key, **data["tenants"][key])

    def add(
        self,
        name: str,
        tenant_id: str,
        client_id: str,
        make_active: bool = True,
        domain: str | None = None,
        permission_set: str = "readOnly",
    ) -> Tenant:
        name, tenant_id, client_id = name.strip(), tenant_id.strip(), client_id.strip()
        if not _NAME.match(name):
            raise UserInputError("Tenant name: letters, digits, space, '.', '_' or '-', max 64.")
        if not (_GUID.match(tenant_id) or _DOMAIN.match(tenant_id)):
            raise UserInputError("tenant_id must be the Directory (tenant) ID GUID or a domain.")
        if not _GUID.match(client_id):
            raise UserInputError("client_id must be the Application (client) ID GUID.")
        if permission_set not in ("readOnly", "full"):
            raise UserInputError("permission_set must be 'readOnly' or 'full'.")
        tenant = Tenant(name, tenant_id, client_id, domain, permission_set)
        data = self._read()
        data["tenants"][name] = {
            k: v for k, v in asdict(tenant).items() if k != "name" and v is not None
        }
        if make_active or not data["active"]:
            data["active"] = name
        self._write(data)
        return tenant

    def use(self, name: str) -> Tenant:
        tenant = self.get(name)
        data = self._read()
        data["active"] = tenant.name
        self._write(data)
        return tenant
