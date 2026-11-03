"""How a baseline's configuration profiles landed on each device (device_results, profiles part).

Settings Catalog policies: Intune's reports API, per policy which devices report it
(getConfigurationPolicyDevicesReport) and per device every setting's status and error code
(getConfigurationSettingsReport). Custom profiles: one status per device (deviceStatuses); a
custom profile is installed or not as a whole.

Each setting that didn't succeed is matched with the device requirements generate_policies
recorded (plan.json), so "Not applicable" on an unsupervised Mac reads as expected, not as a fault.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from .graph import GraphClient, GraphError
from .platforms import Platform


# Intune's setting status numbers in the reports API
SETTING_STATUS = {0: "unknown", 1: "not_applicable", 2: "succeeded", 3: "succeeded", 4: "error", 5: "error",
                  6: "conflict", 7: "not_assigned", 8: "error"}
POLICY_STATUS = {0: "unknown", 1: "not_applicable", 2: "succeeded", 3: "succeeded", 4: "error", 5: "error",
                 6: "conflict", 7: "not_assigned", 8: "error"}
# Custom profile deviceStatuses (and the reports API's ReportStatus text)
CUSTOM_STATUS = {"compliant": "succeeded", "remediated": "succeeded", "succeeded": "succeeded", "notapplicable": "not_applicable",
                 "noncompliant": "error", "error": "error", "conflict": "conflict", "unknown": "pending",
                 "notassigned": "not_assigned"}
TOP = 1000


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


def _rows(graph: GraphClient, report: str, body: dict[str, Any]) -> list[dict[str, Any]]:
    """All rows of a reports API call as dicts (it answers with Schema + Values, paged by skip)."""
    out: list[dict[str, Any]] = []
    skip = 0
    while True:
        page = graph.request("POST", f"/deviceManagement/reports/{report}", body={**body, "top": TOP, "skip": skip})
        cols = [c["Column"] for c in page.get("Schema", [])]
        values = page.get("Values", [])
        out += [dict(zip(cols, v)) for v in values]
        if len(values) < TOP or len(out) >= int(page.get("TotalRowCount", len(out))):
            return out
        skip += TOP


def own_profiles(graph: GraphClient, platform: Platform, prefix: str) -> list[dict[str, Any]]:
    """This baseline's Settings Catalog policies and custom profiles in the tenant."""
    found = [{"id": p["id"], "name": p["name"], "type": "settings_catalog", "modified": p.get("lastModifiedDateTime")}
             for p in graph.get_all("/deviceManagement/configurationPolicies",
                                    {"$select": "id,name,lastModifiedDateTime",
                                     "$filter": f"platforms has '{platform.mscp_os}'"})
             if str(p.get("name", "")).startswith(prefix)]
    found += [{"id": p["id"], "name": p["displayName"], "type": "custom_profile",
               "modified": p.get("lastModifiedDateTime")}
              for p in graph.get_all("/deviceManagement/deviceConfigurations",
                                     {"$select": "id,displayName,lastModifiedDateTime"})
              if p.get("@odata.type") == platform.custom_profile_type and str(p.get("displayName", "")).startswith(prefix)]
    return sorted(found, key=lambda p: p["name"])


def _expected(requirements: list[dict[str, Any]], policy: str) -> dict[str, dict[str, Any]]:
    """Normalized last key segment -> requirement, for this policy's rules."""
    out = {}
    for r in requirements:
        if r.get("policy") != policy:
            continue
        for s in r.get("settings", []):
            key = s.split(" ", 1)[-1].split(".")[-1]
            out[_norm(key)] = r
    return out


def gather(graph: GraphClient, platform: Platform, prefix: str, plan: dict[str, Any] | None, *,
           device_ids: set[str] | None = None, device: str | None = None) -> dict[str, Any]:
    """Per device: each of this baseline's profiles with its status and, for Settings Catalog,
    the settings that didn't succeed (with error code, rules and whether a device requirement
    explains it). ``device`` filters by name; ``device_ids`` limits to these Intune device IDs."""
    plan = plan or {}
    reqs = plan.get("device_requirements", [])
    rules_of = {p["name"]: p.get("rules", []) for p in plan.get("policies", [])}
    profiles = own_profiles(graph, platform, prefix)
    per_device: dict[str, dict[str, Any]] = defaultdict(lambda: {"profiles": []})

    def wanted(did: str, name: str) -> bool:
        if device_ids is not None and did not in device_ids:
            return False
        return not device or device.lower() in str(name).lower()

    for prof in profiles:
        if prof["type"] == "custom_profile":
            try:
                statuses = graph.get_all(f"/deviceManagement/deviceConfigurations/{prof['id']}/deviceStatuses")
            except GraphError as e:
                if e.status != 404:
                    raise
                statuses = []
            for st in statuses:
                did = str(st.get("id", "")).split("_")[-1]
                if not did or not wanted(did, st.get("deviceDisplayName", "")):
                    continue
                d = per_device[did]
                d.setdefault("device", st.get("deviceDisplayName"))
                d.setdefault("user", st.get("userPrincipalName"))
                state = CUSTOM_STATUS.get(str(st.get("status", "")).lower(), str(st.get("status")))
                d["profiles"].append({
                    "policy": prof["name"], "type": "custom_profile", "state": state,
                    "last_reported": st.get("lastReportedDateTime"), "rules": rules_of.get(prof["name"], []),
                    **({"expected": [r["requirement"] for r in reqs if r.get("policy") == prof["name"]]}
                       if state != "succeeded" and any(r.get("policy") == prof["name"] for r in reqs) else {}),
                })
            continue
        rows = _rows(graph, "getConfigurationPolicyDevicesReport", {
            "select": ["DeviceName", "UPN", "ReportStatus", "PspdpuLastModifiedTimeUtc", "IntuneDeviceId",
                       "UserId", "PolicyStatus", "PolicyBaseTypeName"],
            "filter": f"(PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') and (PolicyId eq '{prof['id']}')",
            "orderBy": []})
        expected = _expected(reqs, prof["name"])
        for row in rows:
            did = row.get("IntuneDeviceId", "")
            if not did or not wanted(did, row.get("DeviceName", "")):
                continue
            d = per_device[did]
            d.setdefault("device", row.get("DeviceName"))
            d.setdefault("user", row.get("UPN"))
            settings = _rows(graph, "getConfigurationSettingsReport", {
                "select": ["SettingName", "SettingStatus", "ErrorCode", "SettingId", "SettingInstanceId"],
                "filter": f"(PolicyId eq '{prof['id']}') and (DeviceId eq '{did}') and (UserId eq '{row.get('UserId', '')}')"})
            counts: Counter = Counter()
            problems = []
            for s in settings:
                status = SETTING_STATUS.get(int(s.get("SettingStatus") or 0), "unknown")
                counts[status] += 1
                if status == "succeeded":
                    continue
                name = str(s.get("SettingName", ""))
                # "Install OS Updates" or the nested "Install OS Updates AutomaticActions/InstallOSUpdates"
                hit = next((expected[k] for k in (_norm(name.split(" ")[-1].split("/")[-1]), _norm(name))
                            if k in expected), None)
                entry = {"setting": name, "state": status}
                if s.get("ErrorCode"):
                    entry["error_code"] = s["ErrorCode"]
                if "(Deprecated)" in name:
                    entry["expected"] = "Intune marks this setting deprecated"
                if hit:
                    entry["rule"] = hit["rule"]
                    entry["expected"] = hit["requirement"]
                problems.append(entry)
            d["profiles"].append({
                "policy": prof["name"], "type": "settings_catalog",
                "state": CUSTOM_STATUS.get(_norm(row.get("ReportStatus") or ""), _norm(row.get("ReportStatus") or ""))
                         if row.get("ReportStatus") else POLICY_STATUS.get(int(row.get("PolicyStatus") or 0), "unknown"),
                "last_reported": row.get("PspdpuLastModifiedTimeUtc"), "settings": dict(counts),
                **({"not_succeeded": problems} if problems else {}),
            })
    devices = [{"id": did, **d} for did, d in sorted(per_device.items(), key=lambda kv: str(kv[1].get("device")))]
    not_ok = [p for d in devices for p in d["profiles"] if p["type"] == "custom_profile" and p["state"] != "succeeded"]
    settings_bad = [s for d in devices for p in d["profiles"] for s in p.get("not_succeeded", [])]
    summary = {
        "profiles": len(profiles), "devices": len(devices),
        "settings_succeeded": sum(p.get("settings", {}).get("succeeded", 0) for d in devices for p in d["profiles"]),
        "settings_not_succeeded": len(settings_bad),
        "explained_by_device_requirements": sum(1 for s in settings_bad if s.get("expected")),
        "unexplained": sum(1 for s in settings_bad if not s.get("expected") and s["state"] != "not_applicable"),
        "custom_profiles_not_installed": len(not_ok),
    }
    return {"summary": summary, "devices": devices, "profiles": [p["name"] for p in profiles]}


def merge(parts: list[tuple[str, dict | None, dict[str, Any]]]) -> dict[str, Any]:
    """Results of the supervised and unsupervised sets of one baseline as one: each profile says
    which variant it belongs to; a device that got both is listed once."""
    devices: dict[str, dict[str, Any]] = {}
    summary: Counter = Counter()
    names: list[str] = []
    for variant, _, got in parts:
        names += got["profiles"]
        summary.update({k: v for k, v in got["summary"].items() if k != "profiles"})
        for d in got["devices"]:
            into = devices.setdefault(d["id"], {k: v for k, v in d.items() if k != "profiles"} | {"profiles": []})
            into["profiles"] += [{**p, "variant": variant} for p in d["profiles"]]
    out = sorted(devices.values(), key=lambda d: str(d.get("device")))
    for d in out:
        if len({p["variant"] for p in d["profiles"]}) > 1:
            d["both_variants"] = ("This device gets the supervised and the unsupervised set; assign them to "
                                  "different groups.")
    return {"summary": {**dict(summary), "profiles": len(names), "devices": len(out)},
            "devices": out, "profiles": names, "variants": [v for v, _, _ in parts]}
