"""Self-test: generate everything for every mSCP baseline and check it, offline and against Intune.

Catches the classes of bugs found by hand so far, without a Mac:

* structure of our output: profiles that don't parse, Managed Client (MCX) payloads in the flat
  form macOS ignores, the same profile key in two profiles, list keys split across profiles,
  rules that end nowhere or with a false reason, scripts that don't parse, compliance rules JSON
  that names settings the discovery script never prints;
* mapping: a catalog setting whose payload domain isn't the one mSCP sets (the screensaver
  idleTime vs user_idletime mistake), catalog settings that exist but whose value didn't fit
  (silently delivered by a custom profile instead);
* Intune itself (round trip, opt-in): every object for all_rules is created unassigned under the
  prefix ``AIB-SELFTEST``, read back and compared, then deleted. Only objects with that prefix are
  ever deleted.

What it can't tell is whether a Mac honours a setting: that stays the inventory's job.
"""

from __future__ import annotations

import base64
import json
import plistlib
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import compliance, generate, inventory, push, remediation, requirements, tailoring
from .catalog import SettingDefinitions
from .graph import GraphClient, GraphError
from .coverage import value_matches
from .mapping import DDM_PREFIX, MCX, expected_settings, forms
from .platforms import Platform

VERSIONS = {Platform.MACOS: ("27.0", "26.0"), Platform.IOS: ("27.0", "26.0")}
PREFIX = "AIB-SELFTEST"
# Settings Intune requires next to a baseline's that have no default: any valid value will do here.
TEST_VALUES = {"com.apple.screensaver_modulename": "Flurry", "com.apple.screensaver.user_modulename": "Flurry"}
INNER = re.compile(r"<<'(MSCP_[A-Z]+_END)'\n(.*?)\n\1\n", re.S)


@dataclass
class Finding:
    severity: str  # error | warning | info
    check: str
    baseline: str
    detail: str
    rule: str = ""


class Report:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.stats: dict[str, Any] = defaultdict(int)

    def add(self, severity: str, check: str, baseline: str, detail: str, rule: str = "") -> None:
        self.findings.append(Finding(severity, check, baseline, detail, rule))

    def summary(self) -> dict[str, Any]:
        by_check: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for f in self.findings:
            by_check[f.check][f.severity] += 1
        return {"stats": dict(self.stats), "by_check": {k: dict(v) for k, v in sorted(by_check.items())},
                "errors": sum(f.severity == "error" for f in self.findings),
                "warnings": sum(f.severity == "warning" for f in self.findings)}

    def as_dict(self) -> dict[str, Any]:
        return {**self.summary(), "findings": [asdict(f) for f in self.findings]}


# ------------------------------------------------------------------ offline


def _payload_items(plist: dict) -> list[tuple[str, str, Any]]:
    """(payload type or MCX/domain, key, value) for every setting in a .mobileconfig."""
    out = []
    for content in plist.get("PayloadContent", []) or []:
        ptype = str(content.get("PayloadType", ""))
        if ptype == MCX:
            for domain, cfg in (content.get("PayloadContent") or {}).items():
                for forced in (cfg or {}).get("Forced", []) or []:
                    for k, v in ((forced or {}).get("mcx_preference_settings") or {}).items():
                        out.append((f"{MCX}/{domain}", k, v))
        else:
            out += [(ptype, k, v) for k, v in content.items() if not k.startswith("Payload")]
    return out


def check_profile(report: Report, baseline: str, name: str, data: bytes) -> list[tuple[str, str, Any]]:
    try:
        plist = plistlib.loads(data)
    except Exception as e:  # noqa: BLE001
        report.add("error", "profile_parses", baseline, f"{name}: {e}")
        return []
    for content in plist.get("PayloadContent", []) or []:
        ptype = content.get("PayloadType")
        if not ptype:
            report.add("error", "profile_shape", baseline, f"{name}: a payload without PayloadType")
        if ptype == MCX:
            extra = [k for k in content if not k.startswith("Payload")]
            inner = content.get("PayloadContent")
            ok = isinstance(inner, dict) and inner and all(
                isinstance(cfg, dict) and isinstance(cfg.get("Forced"), list) and cfg["Forced"]
                and all(isinstance(f, dict) and isinstance(f.get("mcx_preference_settings"), dict)
                        for f in cfg["Forced"]) for cfg in inner.values())
            if extra or not ok:
                report.add("error", "mcx_shape", baseline,
                           f"{name}: Managed Client payload not in PayloadContent/domain/Forced/"
                           f"mcx_preference_settings form (macOS ignores it){'; flat keys ' + str(extra) if extra else ''}")
    return _payload_items(plist)


def check_scripts(report: Report, baseline: str, folder: Path) -> None:
    bash, zsh = shutil.which("bash"), shutil.which("zsh")
    for sh in sorted(folder.glob("*.sh")):
        text = sh.read_text(encoding="utf-8")
        report.stats["scripts"] += 1
        if bash:
            r = subprocess.run([bash, "-n", str(sh)], capture_output=True, text=True)
            if r.returncode:
                report.add("error", "script_syntax", baseline, f"{sh.name} (bash wrapper): {r.stderr.strip()[:300]}")
        m = INNER.search(text)
        if not m:
            report.add("error", "script_syntax", baseline, f"{sh.name}: zsh body not found")
            continue
        if zsh:
            r = subprocess.run([zsh, "--no-rcs", "-n"], input=m.group(2), capture_output=True, text=True)
            if r.returncode:
                report.add("error", "script_syntax", baseline, f"{sh.name} (zsh body): {r.stderr.strip()[:300]}")


def offline(src, defs: SettingDefinitions, platform: Platform, os_version: str, work: Path,
            report: Report, baselines: list[str] | None = None) -> None:
    refs = [r for r in src.list_baselines(platform, os_version)
            if r.source == "mscp" and r.os_version == os_version and (not baselines or r.key in baselines)]
    for ref in refs:
        report.stats["baselines"] += 1
        try:
            _offline_one(src, defs, platform, ref, work / ref.name, report)
        except Exception as e:  # noqa: BLE001 - one broken baseline shouldn't stop the run
            report.add("error", "generate_runs", ref.name, f"{type(e).__name__}: {e}")


def _offline_one(src, defs, platform: Platform, ref, work: Path, report: Report) -> None:
    base = src.load(ref)
    name, ver, mscp = ref.name, ref.os_version, src.mscp_version
    display = tailoring.display_name(ref)
    rules = {r.rule_id: r for p in base.profile for r in p.rules}
    report.stats["rules"] += len(rules)

    # -------- policies
    result = generate.build(base, platform, defs, None, None, dict(TEST_VALUES), os_version=ver)
    policies = generate.write(result, work / "policies", prefix=PREFIX, platform=platform,
                              baseline_display=display, baseline_name=name, os_version=ver, mscp_version=mscp)
    report.stats["policies"] += len(policies)
    # Apple's schema: keys the target OS no longer (or never) has, and payloads Apple doesn't document
    for p in policies:
        for r in p.get("device_requirements", []):
            report.stats["device_requirements"] += 1
            if r.get("not_available") or r.get("removed_in"):
                report.add("warning", "apple_unsupported", name, f"{r['requirement']}: {', '.join(r['settings'])}",
                           r["rule"])
    for sec in result["sections"]:
        for rid, keys in sec.placed.items():
            for ptype, _ in keys:
                if requirements.for_key(platform, ptype, "") is None:
                    report.add("info", "apple_schema", name, f"{ptype} isn't in Apple's device-management schema",
                               rid)
    for a in [a for p in policies for a in p.get("added_because_intune_requires", []) if a.get("needs_value")]:
        report.add("warning", "needs_value", name, f"{a['setting']}: Intune requires it and it has no default")

    # where every rule ended
    placed = {r for s in result["sections"] for r in (*s.catalog_rules, *s.custom_rules)}
    placed |= {r for m in result["merged_lists"] for r in m["rules"]}
    not_policy = {r for v in result["not_policy"].values() for r in v}
    undeliverable = {u["rule"]: u["why"] for u in result["undeliverable"]}
    for rid in sorted(set(rules) - placed - not_policy - set(undeliverable)):
        report.add("error", "rule_accounted", name, "generated nowhere and not reported", rid)
    for rid, why in undeliverable.items():
        r = rules.get(rid)
        if r is not None and "has no configuration profile payload" in why and r.mobileconfig_info:
            report.add("error", "true_reason", name, f"reported as having no payload, but mSCP has one: {why}", rid)
        else:
            report.add("warning", "undeliverable", name, why, rid)

    # catalog: same setting in two policies with different values, payload domain, silent fallbacks
    catalog_values: dict[str, dict[str, str]] = defaultdict(dict)
    for p in policies:
        if p["type"] != "settings_catalog":
            continue
        for line in p["settings"]:
            sid, _, val = line.partition(" = ")
            catalog_values[sid][p["name"]] = val
    for sid, where in catalog_values.items():
        if len(set(where.values())) > 1:
            report.add("error", "catalog_conflict", name, f"{sid}: {where}")
    for sec in result["sections"]:
        for rid, why in sec.catalog_fallbacks.items():
            if rid in sec.custom_rules:
                report.add("warning", "catalog_fallback", name,
                           f"in the catalog but not used ({why}); delivered by a custom profile", rid)
        for rid in sec.catalog_rules:
            for form in forms(rules[rid]):
                for e in expected_settings(rules[rid], form):
                    if not e.in_catalog:
                        continue
                    d = defs.get(e.setting_id)
                    root = str((d or {}).get("rootDefinitionId", "")).lower()
                    want = DDM_PREFIX.get(e.payload_type, e.payload_type).lower()
                    if d and root and not root.startswith(want + "_"):
                        report.add("error", "payload_domain", name,
                                   f"{e.setting_id} belongs to {root.split('_')[0]}, mSCP sets {e.payload_type}", rid)

    # custom profiles: shape, and the same key in two profiles / profile vs catalog
    keys: dict[tuple[str, str], dict[str, Any]] = defaultdict(dict)
    for p in policies:
        if p["type"] != "custom_profile":
            continue
        mc = (work / "policies" / p["file"]).with_suffix(".mobileconfig")
        for ptype, k, v in check_profile(report, name, p["name"], mc.read_bytes()):
            keys[(ptype, k)][p["name"]] = v
    for (ptype, k), where in keys.items():
        values = {json.dumps(v, sort_keys=True, default=str) for v in where.values()}
        if len(where) > 1 and len(values) > 1:  # the same value twice is harmless
            report.add("error", "duplicate_profile_key", name,
                       f"{ptype} {k} has different values in {len(where)} profiles ({where}); a Mac applies one")
        sid = f"{ptype}_{k}".lower()
        for policy, text in catalog_values.get(sid, {}).items():
            for v in where.values():
                if value_matches(text, v, sid) is not True:
                    report.add("error", "profile_and_catalog", name,
                               f"{ptype} {k}: {v!r} in a profile, {text} in {policy}; a Mac gets two values")

    if not platform.supports_custom_compliance:
        return
    # -------- compliance
    comp = compliance.select(base, platform, None)
    cpols = compliance.write(comp, work / "compliance", prefix=PREFIX, platform=platform, baseline_display=display,
                             baseline_name=name, os_version=ver, mscp_version=mscp,
                             more_info=compliance.DEFAULT_MORE_INFO, grace_hours=0)
    report.stats["compliance_policies"] += len(cpols)
    for p in cpols:
        if not p.get("rules_json"):
            continue
        rules_doc = json.loads((work / "compliance" / p["rules_json"]).read_text(encoding="utf-8"))
        script = (work / "compliance" / p["script"]).read_text(encoding="utf-8")
        for r in rules_doc.get("Rules", []):
            if f'"{r["SettingName"]}"' not in script and f"'{r['SettingName']}'" not in script \
                    and r["SettingName"] not in script:
                report.add("error", "compliance_rules_match_script", name,
                           f"{p['name']}: rules JSON has {r['SettingName']}, the script never prints it")
    check_scripts(report, name, work / "compliance")
    # -------- remediation
    rem = remediation.select(base, platform)
    remediation.write(rem, work / "remediation", prefix=PREFIX, platform=platform, baseline_display=display,
                      baseline_name=name, os_version=ver, mscp_version=mscp, frequency="daily")
    check_scripts(report, name, work / "remediation")
    # -------- inventory
    inv = inventory.select(base, platform)
    attrs = inventory.write(inv, work / "inventory", prefix=PREFIX, platform=platform, baseline_display=display,
                            baseline_name=name, os_version=ver, mscp_version=mscp,
                            parent_values=getattr(base, "parent_values", "") or "", attribute_prefix=PREFIX)
    for a in attrs:  # worst case: every value at its cap
        worst = sum(len(r) + inventory.MAX_VALUE + 3 for r in a["rules"]) + 40  # = inventory.worst_size
        if worst > inventory.MAX_OUTPUT:
            report.add("warning", "inventory_size", name,
                       f"{a['name']}: up to {worst} bytes if every value is long (Intune allows 20 KB)")
    check_scripts(report, name, work / "inventory")


# --------------------------------------------------------------- round trip

ENDPOINTS = {  # what we create, in delete order (policies before the scripts they use)
    "config_policy": "/deviceManagement/configurationPolicies",
    "custom_profile": "/deviceManagement/deviceConfigurations",
    "compliance_policy": "/deviceManagement/deviceCompliancePolicies",
    "compliance_script": "/deviceManagement/deviceComplianceScripts",
    "shell_script": push.SHELL_SCRIPTS,
    "custom_attribute": push.CUSTOM_ATTRIBUTES,
}
NAME_FIELD = {"config_policy": "name"}


def leftovers(graph: GraphClient) -> list[tuple[str, str, str]]:
    """(kind, id, name) of every object named with the self-test prefix."""
    found = []
    for kind, ep in ENDPOINTS.items():
        field = NAME_FIELD.get(kind, "displayName")
        try:
            items = graph.get_all(ep, {"$select": f"id,{field}"})
        except GraphError:
            continue
        found += [(kind, i["id"], i.get(field, "")) for i in items if str(i.get(field, "")).startswith(PREFIX + " - ")]
    return found


def _not_found(kind: str, e: GraphError) -> bool:
    """Settings Catalog (DCv2) answers 400, not 404, for an id that no longer exists."""
    return e.status == 404 or (kind == "config_policy" and e.status == 400)


def _gone(graph: GraphClient, kind: str, oid: str) -> bool:
    try:
        graph.get(f"{ENDPOINTS[kind]}/{oid}")
    except GraphError as e:
        return _not_found(kind, e)
    return False


def delete(graph: GraphClient, objects: list[tuple[str, str, str]], report: Report, baseline: str,
           wait=None, tries: int = 7) -> int:
    """Delete, policies before the scripts they use, and confirm each one is gone: Intune accepts
    a discovery script's DELETE while its compliance policy is still being removed, then keeps
    it. What still exists after the retries is reported, by name."""
    import time

    wait = wait or time.sleep
    order = list(ENDPOINTS)
    todo = [o for o in sorted(objects, key=lambda o: order.index(o[0])) if o[2].startswith(PREFIX + " - ")]
    done = 0
    for attempt in range(tries):
        left = []
        for kind, oid, name in todo:
            try:
                graph.request("DELETE", f"{ENDPOINTS[kind]}/{oid}")
            except GraphError as e:
                if not _not_found(kind, e):
                    left.append((kind, oid, name, str(e)))
                    continue
            if _gone(graph, kind, oid):  # a 400 on DELETE is only "gone" if the GET agrees
                done += 1
            else:
                left.append((kind, oid, name, "still there after DELETE"))
        if not left:
            return done
        todo = [(k, o, n) for k, o, n, _ in left]
        if attempt < tries - 1:
            wait(min(2 ** attempt, 15))
    for kind, oid, name, why in left:
        report.add("error", "cleanup", baseline, f"{kind} '{name}' ({oid}) couldn't be deleted: {why}")
    return done


def _b64(text: str | None) -> bytes:
    try:
        return base64.b64decode(text or "")
    except (ValueError, TypeError):
        return b""


def round_trip(src, graph: GraphClient, defs: SettingDefinitions, platform: Platform, os_version: str,
               work: Path, report: Report) -> None:
    """all_rules for this platform/version: create unassigned, read back, compare, delete."""
    ref = src.resolve("all_rules", platform, os_version)
    name = f"{ref.name} (round trip)"
    stale = leftovers(graph)
    if stale:
        report.add("warning", "cleanup", name, f"{len(stale)} AIB-SELFTEST object(s) from an earlier run: "
                   + "; ".join(n for _, _, n in stale))
        report.stats["leftovers_deleted"] += delete(graph, stale, report, name)
    folder = work / f"{ref.name}_roundtrip"
    _offline_one(src, defs, platform, ref, folder, Report())  # its findings belong to the offline run
    created: list[tuple[str, str, str]] = []
    try:
        # configuration
        plan = json.loads(json.dumps({"policies": [
            {**p, "rules": p["rules"], "settings": p["settings"]}
            for p in _policies_from(folder / "policies")]}))
        actions = push.plan_actions(plan, {}, None)
        for r in push.execute(graph, actions, folder / "policies"):
            kind = "config_policy" if r["type"] == "settings_catalog" else "custom_profile"
            if r["result"] == "failed":
                report.add("error", "intune_accepts", name, f"{r['name']}: {r['error']}")
                continue
            created.append((kind, r["id"], r["name"]))
            report.stats["created"] += 1
        check = [{**a, "action": "skip_exists", "existing_id": oid} for a in actions
                 for k, oid, n in created if n == a["name"]]
        for n in push.compare_with_intune(graph, check, folder / "policies"):
            report.add("error", "intune_reads_back", name, f"{n}: Intune's copy differs from what was sent")
        report.stats["compared_same"] += sum(a.get("in_intune") == "same" for a in check)

        if platform.supports_custom_compliance:
            _round_trip_compliance(graph, folder / "compliance", created, report, name)
            for sub, ep, kind in (("remediation", push.SHELL_SCRIPTS, "shell_script"),
                                  ("inventory", push.CUSTOM_ATTRIBUTES, "custom_attribute")):
                plan = {"scripts": [json.loads(f.read_text(encoding="utf-8")) | {"file": f.name, "rules": []}
                                    for f in sorted((folder / sub).glob("*.json"))
                                    if f.name != "plan.json" and not f.name.endswith(".fields.json")]}
                plan["scripts"] = [dict(s, name=s["displayName"]) for s in plan["scripts"]]
                for r in push.execute_remediation(graph, push.plan_remediation(plan, {}, None), folder / sub, ep):
                    if r["result"] == "failed":
                        report.add("error", "intune_accepts", name, f"{r['name']}: {r['error']}")
                        continue
                    created.append((kind, r["id"], r["name"]))
                    report.stats["created"] += 1
                    sent = json.loads((folder / sub / r["file"]).read_text(encoding="utf-8"))
                    got = graph.get(f"{ep}/{r['id']}")
                    if _b64(got.get("scriptContent")) != _b64(sent["scriptContent"]):
                        report.add("error", "intune_reads_back", name, f"{r['name']}: script content differs")
                    else:
                        report.stats["compared_same"] += 1
    finally:
        report.stats["deleted"] += delete(graph, created, report, name)


def _policies_from(folder: Path) -> list[dict]:
    out = []
    for f in sorted(folder.glob("*.json")):
        if f.name == "plan.json":
            continue
        body = json.loads(f.read_text(encoding="utf-8"))
        if "settings" in body:
            out.append({"name": body["name"], "type": "settings_catalog", "file": f.name, "rules": [],
                        "settings": body["settings"]})
        else:
            out.append({"name": body["displayName"], "type": "custom_profile", "file": f.name, "rules": [],
                        "settings": []})
    return out


def _round_trip_compliance(graph: GraphClient, folder: Path, created: list, report: Report, name: str) -> None:
    for f in sorted(folder.glob("*.json")):
        if f.name.endswith((".rules.json", ".script.json")):
            continue
        body = json.loads(f.read_text(encoding="utf-8"))
        script_file = f.with_name(f.name[:-5] + ".script.json")
        try:
            if script_file.exists():
                sbody = json.loads(script_file.read_text(encoding="utf-8"))
                sid = graph.send("POST", ENDPOINTS["compliance_script"], sbody).get("id")
                created.append(("compliance_script", sid, sbody["displayName"]))
                got = graph.get(f"{ENDPOINTS['compliance_script']}/{sid}")
                if _b64(got.get("detectionScriptContent")) != _b64(sbody["detectionScriptContent"]):
                    report.add("error", "intune_reads_back", name, f"{sbody['displayName']}: script content differs")
                body["deviceCompliancePolicyScript"]["deviceComplianceScriptId"] = sid
            pid = graph.send("POST", ENDPOINTS["compliance_policy"], body).get("id")
            created.append(("compliance_policy", pid, body["displayName"]))
            report.stats["created"] += 1 + script_file.exists()
            got = graph.get(f"{ENDPOINTS['compliance_policy']}/{pid}")
            builtin = {k: v for k, v in body.items() if k not in (
                "@odata.type", "displayName", "description", "roleScopeTagIds", "scheduledActionsForRule",
                "deviceCompliancePolicyScript")}
            wrong = {k: (v, got.get(k)) for k, v in builtin.items() if got.get(k) != v}
            if wrong:
                report.add("error", "intune_reads_back", name, f"{body['displayName']}: built-in settings differ {wrong}")
            sent_rules = (body.get("deviceCompliancePolicyScript") or {}).get("rulesContent")
            got_rules = (got.get("deviceCompliancePolicyScript") or {}).get("rulesContent")
            if sent_rules and got_rules and json.loads(_b64(got_rules)) != json.loads(_b64(sent_rules)):
                report.add("error", "intune_reads_back", name, f"{body['displayName']}: rules JSON differs")
            report.stats["compared_same"] += not wrong
        except GraphError as e:
            report.add("error", "intune_accepts", name, f"{body['displayName']}: {e}")


# ------------------------------------------------------------------- output


def write_markdown(report: Report, path: Path, title: str) -> Path:
    s = report.summary()
    lines = [f"# {title}", "", f"**{s['errors']} errors, {s['warnings']} warnings**", "",
             "| Stat | Value |", "|---|---|", *[f"| {k} | {v} |" for k, v in sorted(s["stats"].items())], "",
             "| Check | Errors | Warnings | Info |", "|---|---|---|---|",
             *[f"| {k} | {v.get('error', 0)} | {v.get('warning', 0)} | {v.get('info', 0)} |"
               for k, v in s["by_check"].items()], ""]
    for sev in ("error", "warning", "info"):
        items = [f for f in report.findings if f.severity == sev]
        if not items:
            continue
        lines += [f"## {'Info' if sev == 'info' else sev.title() + 's'}", ""]
        by: dict[str, list[Finding]] = defaultdict(list)
        for f in items:
            by[f.check].append(f)
        for check, fs in sorted(by.items()):
            lines += [f"### {check} ({len(fs)})", ""]
            lines += [f"- `{f.baseline}`{' `' + f.rule + '`' if f.rule else ''}: {f.detail}" for f in fs]
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    """Run the self-test without Claude: python -m apple_intune_baseline.selftest --platform macos --os 27.0"""
    import argparse

    from . import server

    ap = argparse.ArgumentParser(prog="python -m apple_intune_baseline.selftest", description=__doc__.split("\n")[0])
    ap.add_argument("--platform", default="macos", choices=["macos", "ios"])
    ap.add_argument("--os", dest="os_version", default="27.0", choices=["27.0", "26.0"])
    ap.add_argument("--baseline", action="append", dest="baselines", help="only this baseline key (repeatable)")
    ap.add_argument("--round-trip", action="store_true", help="also create/read back/delete AIB-SELFTEST objects")
    ap.add_argument("--cleanup-only", action="store_true", help="only delete AIB-SELFTEST leftovers")
    ap.add_argument("--tenant")
    a = ap.parse_args(argv)
    res = server.self_test(platform=a.platform, os_version=a.os_version, round_trip=a.round_trip,
                           confirm=a.round_trip or a.cleanup_only, cleanup_only=a.cleanup_only,
                           baselines=a.baselines, tenant=a.tenant)
    print(json.dumps({k: v for k, v in res.items() if k != "findings"}, indent=2, default=str))
    for f in (res.get("findings") or [])[:40]:
        print(f"{f['severity']:7} {f['check']:24} {f['baseline']:32} {f.get('rule', '')} {f['detail'][:160]}")
    return 1 if res.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
