"""What a device needs before a setting applies: the OS version it came in and supervision
(and whether Apple has deprecated or removed it).

Read from Apple's device-management schema (bundled as mapping/apple_requirements.json, rebuilt
with tools/build_apple_requirements.py). A Mac or iPhone that doesn't meet them reports the
setting as "Not applicable" in Intune; nothing is wrong with the policy.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

from .mapping import MCX
from .platforms import Platform

SUPERVISED_HOW = {
    Platform.MACOS: "supervised Macs (enrolled through Automated Device Enrollment); virtual machines can't be "
                    "supervised",
    Platform.IOS: "supervised devices (Automated Device Enrollment or Apple Configurator)",
}


@lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    text = files("apple_intune_baseline.mapping").joinpath("apple_requirements.json").read_text(encoding="utf-8")
    return json.loads(text)


def source() -> str:
    d = _data()
    return f"{d['source']} {d.get('commit', '')}".strip()


def _v(s: str) -> tuple[int, ...]:
    parts = [int(x) for x in str(s).split(".") if x.isdigit()]
    while len(parts) < 2:
        parts.append(0)
    return tuple(parts)


def for_key(platform: Platform, payload_type: str, key: str) -> dict[str, Any] | None:
    """Apple's effective support for one payload key ('A.B.C' for nested DDM keys) on this
    platform: introduced / supervised / removed, the deepest override winning. None if unknown."""
    os_ = platform.mscp_os
    types = _data()["types"]
    if payload_type.startswith(MCX + "/"):  # MCX domain: the domain's own payload if Apple has one
        domain = payload_type[len(MCX) + 1:]
        payload_type = domain if domain in types else MCX
    entry = types.get(payload_type)
    if not entry or not os_:
        return None
    eff = dict(entry["payload"].get(os_, {}))
    parts = [p for p in key.split(".") if p]
    for i in range(1, len(parts) + 1):
        eff.update(entry["keys"].get(".".join(parts[:i]), {}).get(os_, {}))
    return eff


def check(platform: Platform, os_version: str, payload_type: str, key: str) -> dict[str, Any] | None:
    """What this key needs beyond the baseline's OS (e.g. 26.4 on a 26 baseline) and supervision.
    None when a device on the baseline's OS meets it without conditions."""
    eff = for_key(platform, payload_type, key)
    if not eff:
        return None
    base = _v(os_version.split(".")[0])  # a "26" baseline covers 26.0 and later
    need: dict[str, Any] = {}
    intro = eff.get("introduced")
    if intro == "n/a":
        need["not_available"] = True
    elif intro and _v(intro) > base:
        need["min_os"] = intro
    if eff.get("removed") and eff["removed"] != "n/a" and _v(eff["removed"]) <= base:
        need["removed_in"] = eff["removed"]
    elif eff.get("deprecated") and eff["deprecated"] != "n/a" and _v(eff["deprecated"]) <= base:
        need["deprecated_in"] = eff["deprecated"]
    if eff.get("supervised"):
        need["supervised"] = True
    return need or None


def describe(platform: Platform, need: dict[str, Any]) -> str:
    os_ = platform.mscp_os
    bits = []
    if need.get("not_available"):
        bits.append(f"not available on {os_}")
    if need.get("removed_in"):
        bits.append(f"removed in {os_} {need['removed_in']}")
    if need.get("deprecated_in"):
        bits.append(f"deprecated since {os_} {need['deprecated_in']}")
    if need.get("min_os"):
        bits.append(f"needs {os_} {need['min_os']} or later")
    if need.get("supervised"):
        bits.append("needs a supervised device" if platform is Platform.IOS else "needs a supervised Mac")
    return ", ".join(bits)


def for_rules(platform: Platform, os_version: str, placed: dict[str, list[tuple[str, str]]],
              where: dict[str, str]) -> list[dict[str, Any]]:
    """One entry per rule with conditions: the strictest across the keys it sets."""
    out = []
    for rule, keys in placed.items():
        need: dict[str, Any] = {}
        settings = []
        for ptype, key in keys:
            n = check(platform, os_version, ptype, key)
            if not n:
                continue
            settings.append(f"{ptype.split('/')[-1]} {key}")
            if n.get("min_os") and _v(n["min_os"]) > _v(need.get("min_os", "0")):
                need["min_os"] = n["min_os"]
            for flag in ("supervised", "not_available"):
                if n.get(flag):
                    need[flag] = True
            for v in ("removed_in", "deprecated_in"):
                if n.get(v):
                    need[v] = n[v]
        if need:
            out.append({"rule": rule, "policy": where.get(rule, ""), **need,
                        "requirement": describe(platform, need), "settings": settings})
    return sorted(out, key=lambda r: (r["policy"], r["rule"]))


def summary(platform: Platform, os_version: str, reqs: list[dict[str, Any]]) -> list[str]:
    """Plain-language notes for the tool result."""
    if not reqs:
        return []
    os_ = platform.mscp_os
    notes = []
    by_min: dict[str, list[str]] = {}
    for r in reqs:
        if r.get("min_os"):
            by_min.setdefault(r["min_os"], []).append(r["rule"])
    for v, rules in sorted(by_min.items(), key=lambda kv: _v(kv[0])):
        notes.append(f"{len(rules)} rule(s) need {os_} {v} or later: devices on an older {os_} report them "
                     f"'Not applicable' until they update ({', '.join(rules)}).")
    sup = [r["rule"] for r in reqs if r.get("supervised")]
    if sup:
        notes.append(f"{len(sup)} rule(s) only apply to {SUPERVISED_HOW[platform]}; other devices report them "
                     f"'Not applicable' ({', '.join(sup)}).")
    gone = [r["rule"] for r in reqs if r.get("not_available") or r.get("removed_in")]
    if gone:
        notes.append(f"{len(gone)} rule(s) set keys Apple doesn't support on {os_} {os_version}: "
                     f"{', '.join(gone)}.")
    old = [r["rule"] for r in reqs if r.get("deprecated_in") and not r.get("removed_in")]
    if old:
        notes.append(f"{len(old)} rule(s) use keys Apple has deprecated on {os_} {os_version}; Intune may show "
                     f"them '(Deprecated)' or 'Not applicable' ({', '.join(old)}).")
    return notes
