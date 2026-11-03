"""Name prefixes, saved per tenant, platform and baseline.

One tenant can hold several baselines on the same platform side by side, e.g. 'CIS TST - macOS -
CIS L1 27.0 - ...' and 'NIST TST - macOS - NIST 800-53 Moderate 27.0 - ...' while a company
evaluates both. So a prefix belongs to (tenant, platform, baseline), and nothing falls back to a
prefix saved for another tenant, platform or baseline: when none is saved, the person is asked,
and the prefixes already used there are offered as suggestions.

Stored in settings.json as ``{"prefixes": {tenant: {platform: {baseline: prefix}}}}``. The old
single ``prefix`` setting is migrated once from the plan.json files earlier runs wrote.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import UserInputError
from .platforms import Platform, parse_platform

STEM = re.compile(r"^(?P<key>.+)_(?:macos|ios)_\d+(?:\.\d+)?$")


def table(settings: dict[str, Any]) -> dict[str, dict[str, dict[str, str]]]:
    return settings.setdefault("prefixes", {})


def saved(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str) -> str | None:
    return (table(settings).get(tenant) or {}).get(plat.value, {}).get(baseline)


def used_here(settings: dict[str, Any], tenant: str, plat: Platform) -> dict[str, str]:
    """baseline -> prefix for one tenant and platform."""
    return dict((table(settings).get(tenant) or {}).get(plat.value, {}))


def remember(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str, prefix: str) -> str | None:
    """Save; returns the prefix it replaced, if different."""
    slot = table(settings).setdefault(tenant, {}).setdefault(plat.value, {})
    old = slot.get(baseline)
    slot[baseline] = prefix
    return old if old and old != prefix else None


def forget(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str) -> str | None:
    slot = (table(settings).get(tenant) or {}).get(plat.value, {})
    return slot.pop(baseline, None)


def resolve(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str, given: str | None,
            *, creating: bool) -> tuple[str, dict[str, Any]]:
    """The prefix to use and how it was chosen.

    creating=True (generate): names new objects and saves a given prefix for this baseline.
    Reading tools pass False: a given prefix reads objects made under it (e.g. an old one) and
    is not saved, so the next generate keeps the saved prefix."""
    given = (given or "").strip()
    if given and not creating:
        return given, {"prefix": given, "prefix_source": "given; not saved (reading only)"}
    if given:
        replaced = remember(settings, tenant, plat, baseline, given)
        info = {"prefix": given, "prefix_source": f"given; saved for {baseline} in {tenant} ({plat.display})"}
        if replaced:
            info["prefix_replaced"] = replaced
        return given, info
    found = saved(settings, tenant, plat, baseline)
    if found:
        return found, {"prefix": found, "prefix_source": f"saved for {baseline} in {tenant} ({plat.display})"}
    others = used_here(settings, tenant, plat)
    hint = ""
    if others:
        hint = " Prefixes already used there: " + ", ".join(
            f"'{p}' ({b})" for b, p in sorted(others.items())) + "."
    legacy = settings.get("legacy_prefix")
    if legacy and legacy not in others.values():
        hint += f" The prefix saved before prefixes were per baseline was '{legacy}'."
    if creating:
        raise UserInputError(
            f"No name prefix saved for {baseline} in {tenant} ({plat.display}).{hint} Ask the person which "
            "prefix to use (a new one keeps this baseline's objects apart, e.g. 'CIS TST' next to "
            "'NIST TST'), then call again with prefix=...; it's saved for this baseline.")
    raise UserInputError(
        f"No name prefix saved for {baseline} in {tenant} ({plat.display}).{hint} Ask the person which "
        "prefix this baseline was pushed with, then call again with prefix=...")


KINDS = ("Settings Catalog", "Custom", "Compliance", "Remediation", "Inventory")


def tool_names(settings: dict[str, Any], tenant: str, plat: Platform, platform_label: str) -> re.Pattern | None:
    """Matches names this tool gives objects for any baseline saved here:
    '<Prefix> - <Platform> - <Baseline> <OS>[ Unsupervised] - <Section> - <Kind>'. None when nothing is saved."""
    known = sorted(set(used_here(settings, tenant, plat).values()), key=len, reverse=True)
    if not known:
        return None
    return re.compile("^(?:" + "|".join(map(re.escape, known)) + ") - " + re.escape(platform_label)
                      + r" - .+ \d+(?:\.\d+)?(?: Unsupervised)? - .+ - (?:" + "|".join(KINDS) + ")$")


def migrate(settings: dict[str, Any], state_dir: Path, active_tenant: str | None) -> bool:
    """Once: move the single 'prefix' setting to per-baseline entries, from earlier plan.json files.
    Plans without a tenant (remediation, inventory) belong to the tenant active now."""
    from .layout import plan_files

    if "prefix" not in settings:
        return False
    legacy = settings.pop("prefix")
    for plan_file in plan_files(state_dir):
        try:
            plan = json.loads(plan_file.read_text(encoding="utf-8"))
            plat = parse_platform(plan.get("platform"))
        except (OSError, ValueError, UserInputError):
            continue
        tenant = plan.get("tenant") or active_tenant
        m = STEM.match(str(plan.get("baseline") or ""))
        key = m.group("key") if m else plan.get("baseline")
        if tenant and plan.get("prefix") and key and not saved(settings, tenant, plat, key):
            remember(settings, tenant, plat, key, plan["prefix"])
    if legacy:
        settings["legacy_prefix"] = legacy
    return True


# ------------------------------------------------- values per baseline

# Values the person chose for settings Intune requires next to a baseline's own (e.g. the
# screensaver module), kept per tenant, platform and baseline like the prefix: one baseline's
# choice must not leak into another's policies.
# settings.json: {"baseline_values": {tenant: {platform: {baseline: {setting_id: value}}}}}


def values(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str) -> dict[str, Any]:
    return dict(((settings.get("baseline_values") or {}).get(tenant) or {}).get(plat.value, {}).get(baseline) or {})


def save_values(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str, new: dict[str, Any]) -> None:
    slot = (settings.setdefault("baseline_values", {}).setdefault(tenant, {})
            .setdefault(plat.value, {}).setdefault(baseline, {}))
    slot.update(new)


def migrate_values(settings: dict[str, Any]) -> bool:
    """Once: the old global 'required_values' go to every baseline that has a saved prefix (the
    ones generated before), so nothing they relied on changes. New baselines start empty."""
    if "required_values" not in settings:
        return False
    old = settings.pop("required_values") or {}
    if old:
        for tenant, plats in table(settings).items():
            for plat_key, baselines in plats.items():
                for baseline in baselines:
                    slot = (settings.setdefault("baseline_values", {}).setdefault(tenant, {})
                            .setdefault(plat_key, {}).setdefault(baseline, {}))
                    for k, v in old.items():
                        slot.setdefault(k, v)
    return True


def drop_values(settings: dict[str, Any], tenant: str, plat: Platform, baseline: str, keys: set[str]) -> list[str]:
    """Remove saved values for these settings (lowercase IDs); returns the ones removed."""
    slot = ((settings.get("baseline_values") or {}).get(tenant) or {}).get(plat.value, {}).get(baseline) or {}
    gone = [k for k in list(slot) if k.lower() in keys]
    for k in gone:
        slot.pop(k)
    return gone
