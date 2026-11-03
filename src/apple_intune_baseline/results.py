"""Per-device results for a baseline: compliance per policy and setting, plus remediation runs.

Read-only. Starts from this baseline's own compliance policies and remediation
scripts (found by the name prefix the generators use), then for each Mac:

* each policy's state and when the Mac last reported it
* the failing settings, mapped back to mSCP rule IDs and titles (custom
  compliance settings already are rule IDs; built-in ones are mapped from the
  Intune property)
* the last run of each remediation script, with its summary line
* ``stale``: the policy result is older than the last remediation run of the
  same section, or older than ``STALE_HOURS``. Intune keeps the previous
  result until the discovery script runs again, so a fixed Mac can look
  non-compliant for hours.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from . import coverage
from .graph import GraphClient, GraphError
from .platforms import Platform

STALE_HOURS = 24
# Intune's names for built-in macOS settings in settingStates -> the policy property.
BUILTIN_ALIASES = {
    "numberofpasswordstoremember": "passwordpreviouspasswordblockcount",
    "passwordrequired": "passwordrequired",
}
DEVICE_FIELDS = "id,deviceName,serialNumber,osVersion,model,userPrincipalName,lastSyncDateTime,complianceState"


FIXED_RE = re.compile(r"\bfixed: (\d+)")


def changed_something(run: dict) -> bool:
    """Did this remediation run change the Mac? Our scripts print 'ok: N, fixed: N, ...'.
    A run that fixed nothing leaves earlier compliance results accurate. Unknown output
    (another script, an error) counts as a change, to be safe."""
    m = FIXED_RE.search(str(run.get("resultMessage") or ""))
    return int(m.group(1)) > 0 if m else True


def _when(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def section_of(name: str, prefix: str, kind: str) -> str:
    """'<prefix><Section> - <kind>' -> Section."""
    rest = name[len(prefix):]
    suffix = f" - {kind}"
    return rest[: -len(suffix)] if rest.endswith(suffix) else rest


def _builtin_rules(platform: Platform) -> dict[str, list[str]]:
    by_prop: dict[str, list[str]] = defaultdict(list)
    for rid, (prop, _kind) in coverage.COMPLIANCE_CHECKS[platform].items():
        by_prop[prop.lower()].append(rid)
    return by_prop


def rules_for_setting(state: dict, platform: Platform, by_prop: dict[str, list[str]],
                      baseline_rules: set[str]) -> list[str]:
    name = str(state.get("settingName") or "")
    if name in baseline_rules or name.endswith("_failed_checks"):
        return [name]
    prop = name.split(".")[-1].lower()  # MacOSCompliancePolicy.PasswordExpirationDays
    prop = BUILTIN_ALIASES.get(prop, prop)
    return [r for r in by_prop.get(prop, []) if r in baseline_rules]


def gather(
    graph: GraphClient,
    platform: Platform,
    prefix: str,
    titles: dict[str, str],
    *,
    device: str | None = None,
    max_devices: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    baseline_rules = set(titles)
    by_prop = _builtin_rules(platform)
    odata = platform.compliance_policy_type
    policies = [
        {"id": p["id"], "name": p["displayName"], "section": section_of(p["displayName"], prefix, "Compliance")}
        for p in graph.get_all("/deviceManagement/deviceCompliancePolicies", {"$select": "id,displayName"})
        if p.get("@odata.type") == odata and str(p.get("displayName", "")).startswith(prefix)
    ]
    scripts = []
    if platform is Platform.MACOS:
        scripts = [
            {"id": s["id"], "name": s["displayName"], "section": section_of(s["displayName"], prefix, "Remediation")}
            for s in graph.get_all("/deviceManagement/deviceShellScripts", {"$select": "id,displayName"})
            if str(s.get("displayName", "")).startswith(prefix) and s["displayName"].endswith(" - Remediation")
        ]

    # Which Macs report on these policies. ($select on deviceStatuses returns a 500.)
    statuses: dict[str, dict[str, dict]] = defaultdict(dict)  # device id -> policy id -> status
    for p in policies:
        for st in graph.get_all(f"/deviceManagement/deviceCompliancePolicies/{p['id']}/deviceStatuses"):
            did = str(st.get("id", "")).split("_")[-1]
            if did:
                statuses[did][p["id"]] = st
    runs: dict[str, dict[str, dict]] = defaultdict(dict)  # device id -> script id -> run
    for s in scripts:
        for run in graph.get_all(f"/deviceManagement/deviceShellScripts/{s['id']}/deviceRunStates"):
            did = str(run.get("id", "")).split(":")[-1]
            if did:
                runs[did][s["id"]] = run

    device_ids = sorted(set(statuses) | set(runs))
    devices: list[dict] = []
    skipped_devices = 0
    for did in device_ids:
        try:
            info = graph.get(f"/deviceManagement/managedDevices/{did}", {"$select": DEVICE_FIELDS})
        except GraphError as e:
            if e.status == 404:
                continue  # retired since
            raise
        if device and device.lower() not in str(info.get("deviceName", "")).lower() \
                and device.lower() != str(info.get("serialNumber", "")).lower():
            continue
        if len(devices) >= max_devices:
            skipped_devices += 1
            continue
        last_fix: dict[str, datetime] = {}
        remediation = []
        for s in scripts:
            run = runs[did].get(s["id"])
            if not run:
                continue
            at = _when(run.get("lastStateUpdateDateTime"))
            if at and changed_something(run):
                last_fix[s["section"]] = at
            remediation.append({"script": s["name"], "section": s["section"], "state": run.get("runState"),
                                "result": run.get("resultMessage") or run.get("errorDescription") or "",
                                "at": run.get("lastStateUpdateDateTime")})
        results = []
        for p in policies:
            st = statuses[did].get(p["id"])
            if not st:
                continue
            reported = _when(st.get("lastReportedDateTime"))
            stale = None
            if reported and p["section"] in last_fix and reported < last_fix[p["section"]]:
                stale = "reported before the last remediation run fixed something"
            elif reported and now - reported > timedelta(hours=STALE_HOURS):
                stale = f"no report for over {STALE_HOURS} hours"
            failing, settings, checks = [], [], 0
            try:
                states = graph.get_all(
                    f"/deviceManagement/managedDevices/{did}/deviceCompliancePolicyStates/{p['id']}/settingStates")
            except GraphError as e:
                if e.status != 404:
                    raise
                states = []
            for s_ in states:
                checks += 1
                passed = str(s_.get("state", "")).lower() in ("compliant", "notapplicable")
                rids = rules_for_setting(s_, platform, by_prop, baseline_rules) or [str(s_.get("settingName"))]
                for rid in rids:
                    entry = {"rule": rid, "title": titles.get(rid, ""), "state": s_.get("state"),
                             "setting": s_.get("setting")}
                    settings.append(entry)
                    if not passed:
                        failing.append(entry)
            results.append({"policy": p["name"], "section": p["section"], "state": st.get("status"),
                            "last_reported": st.get("lastReportedDateTime"), "checks": checks,
                            "failing": failing, "settings": settings, **({"stale": stale} if stale else {})})
        devices.append({
            "device": info.get("deviceName"), "id": did, "serial": info.get("serialNumber"),
            "user": info.get("userPrincipalName"), "os": info.get("osVersion"), "model": info.get("model"),
            "last_sync": info.get("lastSyncDateTime"), "compliance": info.get("complianceState"),
            "policies": results, "remediation": remediation,
        })

    failing_count = Counter(f["rule"] for d in devices for p in d["policies"] for f in p["failing"])
    summary = {
        "devices": len(devices),
        "compliant": sum(1 for d in devices if all(p["state"] == "compliant" for p in d["policies"])),
        "with_failures": sum(1 for d in devices if any(p["failing"] for p in d["policies"])),
        "stale_results": sum(1 for d in devices for p in d["policies"] if p.get("stale")),
        "top_failing": [{"rule": r, "title": titles.get(r, ""), "devices": n} for r, n in failing_count.most_common(10)],
    }
    return {
        "generated_at": now.isoformat(), "summary": summary, "devices": devices,
        "policies": [p["name"] for p in policies], "scripts": [s["name"] for s in scripts],
        **({"not_shown": skipped_devices} if skipped_devices else {}),
    }


def rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per Mac and check (failing) or per Mac and policy (nothing failing): for CSV."""
    out = []
    for d in data["devices"]:
        base = {"device": d["device"], "serial": d["serial"], "user": d["user"], "os": d["os"],
                "device_compliance": d["compliance"], "last_sync": d["last_sync"]}
        for p in d["policies"]:
            common = {**base, "policy": p["policy"], "section": p["section"], "policy_state": p["state"],
                      "last_reported": p["last_reported"], "stale": p.get("stale", "")}
            if p["failing"]:
                for f in p["failing"]:
                    out.append({**common, "rule": f["rule"], "title": f["title"], "result": f["state"]})
            else:
                out.append({**common, "rule": "", "title": "", "result": "all checks pass" if p["checks"] else ""})
    return out
