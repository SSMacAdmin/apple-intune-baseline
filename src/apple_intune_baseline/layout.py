"""Where generated files and reports live: per tenant, then per baseline.

    ~/.apple-intune-baseline/
        tenants.json, settings.json, auth/, settings_catalog_definitions.json   shared
        mscp-custom/                                                          shared (tailored baselines)
        tenants/<tenant>/generated/<baseline>/{policies,policies-unsupervised,compliance,remediation,inventory}/
        tenants/<tenant>/reports/<baseline>/<baseline>_{compliance,inventory}_<UTC time>.{html,pdf,csv,json}

Baseline above type: everything for one evaluation (e.g. NIST next to CIS) is one folder.
Earlier versions used <home>/generated*/<baseline>/ and <home>/reports/; ``migrate`` moves those
once (to the tenant in their plan.json, else the active tenant) and removes the empty old folders.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

KINDS = ("policies", "policies-unsupervised", "compliance", "remediation", "inventory")
OLD_GENERATED = {"generated": "policies", "generated-compliance": "compliance",
                 "generated-remediation": "remediation", "generated-inventory": "inventory"}
_REPORT = re.compile(r"^(?P<ref>.+_(?:macos|ios)_\d+(?:\.\d+)?)_(?:(?P<inv>inventory)_)?(?P<stamp>\d{8}-\d{4})"
                     r"(?P<ext>\.[A-Za-z]+)$")


def folder_name(tenant: str) -> str:
    """A tenant name as a folder name (it's the name given to add_tenant, e.g. 'ssmacadmin')."""
    return re.sub(r"[^A-Za-z0-9._ -]+", "_", tenant).strip(" .") or "tenant"


def tenant_dir(home: Path, tenant: str) -> Path:
    return home / "tenants" / folder_name(tenant)


def generated(home: Path, tenant: str, baseline: str, kind: str) -> Path:
    assert kind in KINDS, kind
    return tenant_dir(home, tenant) / "generated" / baseline / kind


def reports(home: Path, tenant: str, baseline: str) -> Path:
    return tenant_dir(home, tenant) / "reports" / baseline


def plan_files(home: Path) -> list[Path]:
    """Every plan.json, new layout and old (for migrations that run before or after this one)."""
    new = sorted(home.glob("tenants/*/generated/*/*/plan.json"))
    old = sorted(p for folder in OLD_GENERATED for p in (home / folder).glob("*/plan.json"))
    return new + old


def _active_tenant(home: Path) -> str | None:
    try:
        return json.loads((home / "tenants.json").read_text(encoding="utf-8")).get("active")
    except (OSError, ValueError):
        return None


def migrate(home: Path) -> list[str]:
    """Move the old layout into the new one, once. Returns what moved (for the log/tests).
    Nothing is overwritten: a folder that already exists at the destination stays where it was."""
    old_dirs = [home / f for f in OLD_GENERATED if (home / f).is_dir()]
    old_reports = home / "reports"
    if not old_dirs and not old_reports.is_dir():
        return []
    active = _active_tenant(home)
    moved: list[str] = []
    for folder in old_dirs:
        kind = OLD_GENERATED[folder.name]
        for d in sorted(p for p in folder.iterdir() if p.is_dir()):
            try:
                tenant = json.loads((d / "plan.json").read_text(encoding="utf-8")).get("tenant")
            except (OSError, ValueError):
                tenant = None
            tenant = tenant or active
            if not tenant:
                continue  # no tenant configured yet: leave it
            dest = generated(home, tenant, d.name, kind)
            if dest.exists():
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(d), str(dest))
            moved.append(f"{folder.name}/{d.name} -> {dest.relative_to(home)}")
        _remove_if_empty(folder)
    if old_reports.is_dir() and active:
        for f in sorted(p for p in old_reports.iterdir() if p.is_file()):
            m = _REPORT.match(f.name)
            if not m:
                continue
            kind = "inventory" if m.group("inv") else "compliance"
            dest = reports(home, active, m.group("ref")) / f"{m.group('ref')}_{kind}_{m.group('stamp')}{m.group('ext')}"
            if dest.exists():
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), str(dest))
            moved.append(f"reports/{f.name} -> {dest.relative_to(home)}")
        _remove_if_empty(old_reports)
    return moved


def _remove_if_empty(folder: Path) -> None:
    for junk in (".DS_Store",):
        (folder / junk).unlink(missing_ok=True)
    try:
        folder.rmdir()
    except OSError:
        pass
