"""Tailored baselines, in mSCP's own format.

* A tailored baseline is an ordinary mSCP baseline YAML in the workspace's
  ``mscp-custom/baselines`` folder: the rules it keeps, per section, with the
  parent baseline's ``parent_values`` so untouched values follow the parent.
  A ``tailoring`` block records where it came from and why rules were left out
  (mSCP ignores keys it doesn't know).
* A changed value is an mSCP rule customization (``mscp-custom/rules/<id>.yaml``
  with ``odv.custom``), written through mSCP's own ``write_odv_custom_rule``.
  Like in mSCP, that value is organization-wide: it applies to every baseline
  in this workspace that has the rule.
"""

from __future__ import annotations

import re
from datetime import date
from typing import TYPE_CHECKING, Any

import yaml

from . import classify
from .errors import UserInputError
from .platforms import Platform

if TYPE_CHECKING:
    from .mscp_source import BaselineRef, MscpSource

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,48}$")

BASELINE_NAMES = {
    "cis_lvl1": "CIS L1",
    "cis_lvl2": "CIS L2",
    "cisv8": "CIS Controls v8",
    "800-53r5_low": "NIST 800-53r5 Low",
    "800-53r5_moderate": "NIST 800-53r5 Moderate",
    "800-53r5_high": "NIST 800-53r5 High",
    "800-171": "NIST 800-171",
    "cmmc_lvl1": "CMMC L1",
    "cmmc_lvl2": "CMMC L2",
    "cmmc_lvl3": "CMMC L3",
    "cnssi-1253_low": "CNSSI 1253 Low",
    "cnssi-1253_moderate": "CNSSI 1253 Moderate",
    "cnssi-1253_high": "CNSSI 1253 High",
    "disa_stig": "DISA STIG",
    "hicp_lp": "HICP LP",
}


def read_tailoring(ref: BaselineRef) -> dict[str, Any]:
    if ref.source != "workspace":
        return {}
    try:
        data = yaml.safe_load(ref.path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return data.get("tailoring") or {}


def _key(baseline: str) -> str:
    """'cis_lvl1_macos_26.0' or 'cis_lvl1' -> 'cis_lvl1'."""
    m = re.match(r"^(?P<key>.+)_(?:macos|ios)_\d+(?:\.\d+)?$", baseline.strip())
    return m["key"] if m else baseline.strip()


def _carry_from(src: MscpSource, platform: Platform, prev: BaselineRef, os_version: str) -> dict[str, Any]:
    """What a tailored baseline changed relative to its source, to re-apply on another OS version.
    Added rules are read from the file (older tailorings didn't record them): rules in the tailored
    copy that its source baseline doesn't have."""
    data = yaml.safe_load(prev.path.read_text(encoding="utf-8")) or {}
    t = data.get("tailoring") or {}
    m = re.match(r"^(?P<key>.+)_(?:macos|ios)_\d+(?:\.\d+)?$", str(t.get("source", "")))
    if not m:
        raise UserInputError(f"{prev.name} doesn't say which mSCP baseline it came from; pass from_baseline.")
    key = m["key"]
    old_parent = src.resolve(key, platform, prev.os_version)
    old_rules = {rid for p in (yaml.safe_load(old_parent.path.read_text(encoding="utf-8")) or {}).get("profile", [])
                 for rid in p.get("rules", [])}
    mine = [rid for p in data.get("profile", []) for rid in p.get("rules", [])]
    included = list(dict.fromkeys([*t.get("included", []), *(r for r in mine if r not in old_rules)]))
    return {"source_key": key, "from": prev.name, "display_name": t.get("display_name"),
            "excluded": dict(t.get("excluded") or {}), "values": dict(t.get("values") or {}),
            "included": included}


def display_name(ref: BaselineRef) -> str:
    """Short name used in Intune policy names, e.g. 'CIS L1'."""
    t = read_tailoring(ref)
    if t.get("display_name"):
        return str(t["display_name"])
    return BASELINE_NAMES.get(ref.key, ref.key.replace("_", " ").upper())


def _coerce(rule, value: Any) -> Any:
    """Check a new value against the rule's ODV hint, as mSCP's tailoring does."""
    hint = (rule.odv or {}).get("hint") or {}
    dtype = str(hint.get("datatype", "")).lower()
    validation = hint.get("validation") or {}
    if dtype == "number":
        try:
            num = float(value)
        except (TypeError, ValueError):
            raise UserInputError(f"{rule.rule_id} needs a number ({hint.get('description', '')}).") from None
        value = int(num) if num.is_integer() else num
        if "min" in validation and value < validation["min"]:
            raise UserInputError(f"{rule.rule_id}: {value} is below the minimum {validation['min']}.")
        if "max" in validation and value > validation["max"]:
            raise UserInputError(f"{rule.rule_id}: {value} is above the maximum {validation['max']}.")
    elif dtype == "boolean":
        if isinstance(value, str):
            if value.lower() not in ("true", "false"):
                raise UserInputError(f"{rule.rule_id} needs true or false.")
            value = value.lower() == "true"
        value = bool(value)
    elif dtype == "string":
        value = str(value)
        if "regex" in validation and not re.fullmatch(str(validation["regex"]), value):
            raise UserInputError(f"{rule.rule_id}: '{value}' doesn't match {validation['regex']}.")
    return value


def tailor(
    src: MscpSource,
    platform: Platform,
    name: str,
    from_baseline: str | None = None,
    os_version: str | None = None,
    exclude: list[str] | None = None,
    include: list[str] | None = None,
    values: dict[str, Any] | None = None,
    reset_values: list[str] | None = None,
    reason: str | None = None,
    display: str | None = None,
) -> dict[str, Any]:
    name = name.strip().lower()
    if not NAME_RE.match(name):
        raise UserInputError(
            "Use a short name with lowercase letters, digits, '-' or '_', e.g. 'contoso_cis_lvl1'."
        )
    os_version = f"{float(os_version):.1f}" if os_version else None
    existing = [
        r for r in src.list_baselines(platform, os_version)
        if r.source == "workspace" and r.key == name and (not os_version or r.os_version == os_version)
    ]
    carried: dict[str, Any] | None = None
    if existing:
        ref = max(existing, key=lambda r: float(r.os_version))
        data = yaml.safe_load(ref.path.read_text(encoding="utf-8")) or {}
        created = False
        if from_baseline and from_baseline not in (data.get("tailoring") or {}).get("source", ""):
            raise UserInputError(
                f"'{name}' already exists, tailored from {(data.get('tailoring') or {}).get('source')}. "
                "Leave out from_baseline to change it, or pick another name."
            )
    else:
        other = [r for r in src.list_baselines(platform) if r.source == "workspace" and r.key == name]
        if other and os_version:
            # Same tailored baseline for another OS version: carry its tailoring onto mSCP's
            # version of the same source baseline (e.g. ssmacadmin_cis_lvl1 27.0 -> 26.0), also
            # when the source is named again; a different source would be a different baseline.
            carried = _carry_from(src, platform, max(other, key=lambda r: float(r.os_version)), os_version)
            if from_baseline and _key(from_baseline) != carried["source_key"]:
                raise UserInputError(
                    f"'{name}' is tailored from {carried['source_key']} on {carried['from']}. For another OS "
                    f"version, leave out from_baseline (its tailoring is copied); for a baseline from "
                    f"{from_baseline}, pick another name.")
            from_baseline = carried["source_key"]
        if not from_baseline:
            raise UserInputError(f"No tailored baseline '{name}' yet. Say which baseline to start from (from_baseline).")
        parent = src.resolve(from_baseline, platform, os_version)
        if parent.source == "workspace":
            raise UserInputError("Start from an mSCP baseline, not another tailored one.")
        data = yaml.safe_load(parent.path.read_text(encoding="utf-8")) or {}
        data["title"] = f"{data.get('title', parent.name)} (tailored: {name})"
        data["tailoring"] = {
            "source": parent.name,
            "created": date.today().isoformat(),
            "display_name": display or (carried or {}).get("display_name") or display_name(parent),
            "excluded": {},
            "values": {},
        }
        created = True
        if carried:
            data["tailoring"]["copied_from"] = carried["from"]
            parent_rules = {rid for p in data.get("profile", []) for rid in p.get("rules", [])}
            for p in data.get("profile", []):
                p["rules"] = [rid for rid in p.get("rules", []) if rid not in carried["excluded"]]
            data["tailoring"]["excluded"] = {rid: why for rid, why in carried["excluded"].items()
                                             if rid in parent_rules}
            data["tailoring"]["values"] = dict(carried["values"])
            include = list(dict.fromkeys([*carried["included"], *(include or [])]))
    ver = f"{float(data['platform']['version']):.1f}"
    path = src.custom_baselines_dir / f"{name}_{platform.value}_{ver}.yaml"
    t = data.setdefault("tailoring", {})
    t.setdefault("excluded", {})
    t.setdefault("values", {})
    if display:
        t["display_name"] = display

    library = src.rule_library(platform, ver)
    profiles: list[dict] = data.setdefault("profile", [])
    in_baseline = {rid: p for p in profiles for rid in p.get("rules", [])}

    changes: dict[str, list] = {"excluded": [], "included": [], "values": [], "values_reset": []}

    unknown = [r for r in exclude or [] if r not in in_baseline]
    if unknown:
        raise UserInputError(f"Not in this baseline, can't exclude: {', '.join(unknown)}")
    for rid in exclude or []:
        in_baseline[rid]["rules"].remove(rid)
        t["excluded"][rid] = reason or ""
        if rid in t.get("included", []):
            t["included"].remove(rid)
        changes["excluded"].append(rid)

    if carried:
        changes["not_on_this_os"] = [r for r in include or [] if r not in library]
        include = [r for r in include or [] if r in library]
    unknown = [r for r in include or [] if r not in library]
    if unknown:
        raise UserInputError(f"No such {platform.display} rule in mSCP {ver}: {', '.join(unknown)}")
    for rid in include or []:
        if rid in in_baseline and rid not in (exclude or []):
            continue
        section = library[rid].section
        prof = next((p for p in profiles if p.get("section") == section), None)
        if prof is None:
            prof = {"section": section, "rules": []}
            profiles.append(prof)
        prof["rules"] = sorted({*prof.get("rules", []), rid})
        t["excluded"].pop(rid, None)
        if rid not in t.setdefault("included", []):
            t["included"].append(rid)
        changes["included"].append(rid)

    kept = {rid for p in profiles for rid in p.get("rules", [])}
    parent_values = data.get("parent_values", "")
    for rid, value in (values or {}).items():
        rule = library.get(rid)
        if rule is None or rid not in kept:
            raise UserInputError(f"{rid} isn't in this tailored baseline, so its value can't be set.")
        if not rule.odv:
            raise UserInputError(f"{rid} has no organization-defined value to change.")
        before = classify.odv_value(rule, parent_values)
        new = _coerce(rule, value)
        rule.write_odv_custom_rule(new)
        t["values"][rid] = new
        changes["values"].append({"rule": rid, "from": before, "to": new})
    for rid in reset_values or []:
        rule = library.get(rid)
        if rule is None:
            raise UserInputError(f"No such rule: {rid}")
        rule.remove_custom_rule()
        t["values"].pop(rid, None)
        changes["values_reset"].append(rid)

    for p in profiles:
        p["rules"] = sorted(p.get("rules", []))
    data["profile"] = [p for p in profiles if p.get("rules")]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    src.invalidate()

    notes = []
    if changes["values"] or changes["values_reset"]:
        notes.append(
            "Changed values are mSCP rule customizations (mscp-custom/rules), so they apply to every "
            "baseline in this workspace with that rule, on macOS and iOS/iPadOS alike, as in mSCP."
        )
    if carried:
        notes.insert(0, f"Tailoring copied from {carried['from']}: {len(t['excluded'])} exclusions, "
                        f"{len(changes['included'])} added rules; values are shared mSCP customizations, "
                        "so they apply here already.")
        gone = sorted(set(carried["excluded"]) - set(t["excluded"]))
        if gone:
            changes["exclusions_not_needed"] = gone  # not in mSCP's version of the source baseline
    return {
        "baseline": name,
        "os_version": ver,
        "created": created,
        "file": str(path),
        "tailored_from": t.get("source"),
        "display_name": t.get("display_name"),
        "rules": len(kept),
        "changes": {k: v for k, v in changes.items() if v},
        "excluded_so_far": t["excluded"],
        "values_so_far": t["values"],
        "notes": notes,
    }
