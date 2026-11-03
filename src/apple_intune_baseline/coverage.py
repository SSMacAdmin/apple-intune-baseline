"""Tenant coverage: which baseline rules a tenant already configures, where, and
whether those policies are assigned.

Two questions per rule:

* **Enforcement**: does a Settings Catalog policy or custom profile set it?
* **Verification**: for rules Intune's built-in compliance settings can check
  (FileVault, Firewall, Gatekeeper, SIP, password rules), does a compliance
  policy check it? The answer decides which rules still need a custom
  compliance script later.

Every policy for the platform is checked, assigned or not: unassigned policies
are often work in progress, and seeing them avoids building the same thing
twice. Read-only.
"""

from __future__ import annotations

import base64
import json
import plistlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .graph import GraphClient, GraphError
from .mapping import MCX, Expected, expected_settings, forms
from .platforms import Platform

if TYPE_CHECKING:
    from mscp.classes.macsecurityrule import Macsecurityrule



# ----------------------------------------------------------------- tenant data


@dataclass
class Policy:
    id: str
    name: str
    kind: str  # "settings_catalog" | "custom_profile" | "compliance_policy"
    assignment: dict[str, Any]  # {"state": ..., "include": [...], "exclude": [...]}
    # setting id (catalog) or "payloadtype|key" (custom) -> list of values
    values: dict[str, list[Any]] = field(default_factory=lambda: defaultdict(list))
    # compliance policies: the policy's own properties
    props: dict[str, Any] = field(default_factory=dict)

    def ref(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "assignment": self.assignment["state"]}


def flatten_setting(instance: dict, out: dict[str, list]) -> None:
    """Walk a Settings Catalog settingInstance tree, collecting (definition id -> values)."""
    sid = instance.get("settingDefinitionId", "")
    t = instance.get("@odata.type", "")
    if "ChoiceSettingInstance" in t and "Collection" not in t:
        v = instance.get("choiceSettingValue") or {}
        out[sid].append(v.get("value"))
        for child in v.get("children", []) or []:
            flatten_setting(child, out)
    elif "ChoiceSettingCollectionInstance" in t:
        for v in instance.get("choiceSettingCollectionValue", []) or []:
            out[sid].append(v.get("value"))
            for child in v.get("children", []) or []:
                flatten_setting(child, out)
    elif "SimpleSettingInstance" in t and "Collection" not in t:
        out[sid].append((instance.get("simpleSettingValue") or {}).get("value"))
    elif "SimpleSettingCollectionInstance" in t:
        out[sid].append([v.get("value") for v in instance.get("simpleSettingCollectionValue", []) or []])
    elif "GroupSettingCollectionInstance" in t:
        for v in instance.get("groupSettingCollectionValue", []) or []:
            for child in v.get("children", []) or []:
                flatten_setting(child, out)
    elif "GroupSettingInstance" in t:
        for child in (instance.get("groupSettingValue") or {}).get("children", []) or []:
            flatten_setting(child, out)


def flatten_custom_payload(payload_b64: str, out: dict[str, list]) -> None:
    """Read a .mobileconfig and collect ("payloadtype|key" -> values)."""
    try:
        plist = plistlib.loads(base64.b64decode(payload_b64))
    except Exception:  # noqa: BLE001 - a broken profile shouldn't stop the check
        return
    for content in plist.get("PayloadContent", []) or []:
        ptype = str(content.get("PayloadType", "")).lower()
        if ptype == MCX.lower():
            # PayloadContent -> domain -> Forced/Set-Once -> mcx_preference_settings; only Forced
            # is enforced. Keyed per domain like mapping.payload_leaves.
            for domain, cfg in (content.get("PayloadContent") or {}).items():
                for forced in (cfg or {}).get("Forced", []) or []:
                    for k, v in ((forced or {}).get("mcx_preference_settings") or {}).items():
                        out[f"{ptype}/{domain.lower()}|{k.lower()}"].append(v)
            continue
        for k, v in content.items():
            if not k.startswith("Payload"):
                out[f"{ptype}|{k.lower()}"].append(v)


def describe_assignments(assignments: list[dict], group_name) -> dict[str, Any]:
    include, exclude = [], []
    for a in assignments:
        target = a.get("target") or {}
        t = target.get("@odata.type", "")
        if "allDevices" in t:
            include.append("All devices")
        elif "allLicensedUsers" in t:
            include.append("All users")
        elif "exclusionGroup" in t:
            exclude.append(group_name(target.get("groupId")))
        elif "groupAssignment" in t:
            include.append(group_name(target.get("groupId")))
    state = "unassigned" if not include else "assigned: " + ", ".join(include)
    if exclude:
        state += " (excluding " + ", ".join(exclude) + ")"
    return {"state": state, "assigned": bool(include), "include": include, "exclude": exclude}


class _Groups:
    """Group ID -> display name, falling back to the ID without GroupMember.Read.All."""

    def __init__(self, graph: GraphClient) -> None:
        self.graph = graph
        self.cache: dict[str, str] = {}
        self.names_available = True

    def __call__(self, gid: str | None) -> str:
        if not gid:
            return "unknown group"
        if gid not in self.cache:
            name = f"group {gid}"
            if self.names_available:
                try:
                    name = self.graph.get(f"/groups/{gid}", {"$select": "displayName"}).get("displayName") or name
                except GraphError:
                    self.names_available = False
            self.cache[gid] = name
        return self.cache[gid]


@dataclass
class TenantScan:
    config: list[Policy]  # Settings Catalog policies and custom profiles
    compliance: list[Policy]
    notes: list[str]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {"settings_catalog": 0, "custom_profile": 0, "compliance_policy": 0}
        for p in self.config + self.compliance:
            out[p.kind] += 1
        return out


def fetch_policies(graph: GraphClient, platform: Platform) -> TenantScan:
    """All Settings Catalog policies, custom profiles and compliance policies for the
    platform, with assignments."""
    groups = _Groups(graph)
    policies: list[Policy] = []
    compliance: list[Policy] = []
    notes: list[str] = []

    catalog = graph.get_all(
        "/deviceManagement/configurationPolicies",
        {"$select": "id,name,platforms,technologies", "$filter": f"platforms has '{platform.mscp_os}'"},
    )
    for item in catalog:
        tech = str(item.get("technologies") or "mdm")
        if "mdm" not in tech and "appleRemoteManagement" not in tech:
            continue  # e.g. enrollment policies, which share the endpoint
        pid = item["id"]
        assignments = graph.get_all(f"/deviceManagement/configurationPolicies/{pid}/assignments")
        p = Policy(pid, item.get("name", pid), "settings_catalog", describe_assignments(assignments, groups))
        for s in graph.get_all(f"/deviceManagement/configurationPolicies/{pid}/settings"):
            flatten_setting(s.get("settingInstance") or {}, p.values)
        policies.append(p)
    decode_choice_options(graph, policies)

    custom_type = platform.custom_profile_type
    for item in graph.get_all("/deviceManagement/deviceConfigurations", {"$select": "id,displayName"}):
        if item.get("@odata.type") != custom_type:
            continue
        pid = item["id"]
        full = graph.get(f"/deviceManagement/deviceConfigurations/{pid}")
        assignments = graph.get_all(f"/deviceManagement/deviceConfigurations/{pid}/assignments")
        p = Policy(pid, item.get("displayName", pid), "custom_profile", describe_assignments(assignments, groups))
        flatten_custom_payload(full.get("payload", ""), p.values)
        policies.append(p)

    compliance_type = platform.compliance_policy_type
    for item in graph.get_all("/deviceManagement/deviceCompliancePolicies"):
        if item.get("@odata.type") != compliance_type:
            continue
        pid = item["id"]
        assignments = graph.get_all(f"/deviceManagement/deviceCompliancePolicies/{pid}/assignments")
        compliance.append(
            Policy(pid, item.get("displayName", pid), "compliance_policy",
                   describe_assignments(assignments, groups), props=item)
        )
        compliance[-1].props["_script_rules"] = custom_compliance_rules(item)

    if not groups.names_available:
        notes.append(
            "Group names need GroupMember.Read.All; showing group IDs. Re-run "
            "setup_app_registration to add it (it updates the existing app)."
        )
    notes.append("Device configuration templates (e.g. Device restrictions, Endpoint protection) are not checked yet.")
    notes.append(
        "Custom compliance scripts are matched by their rules' setting names (an exact mSCP rule ID, "
        "or SIP/Gatekeeper/FileVault/Firewall/stealth mode by keyword); the discovery script itself "
        "isn't inspected."
    )
    return TenantScan(policies, compliance, notes)


_INDEXED = re.compile(r"_\d+$")


def decode_choice_options(graph: GraphClient, policies: list[Policy]) -> None:
    """Choice values like 'softwareupdate_automaticactions_download_0' are option IDs, not
    values: the index says nothing about what it means. Look the option up in the setting
    definition and replace the ID with its real value ('Allowed'). Values that can't be
    looked up stay as they are."""
    wanted = {
        sid
        for p in policies
        for sid, vals in p.values.items()
        if any(isinstance(v, str) and v.lower().startswith(sid.lower() + "_") and _INDEXED.search(v) for v in vals)
    }
    options: dict[str, Any] = {}
    for sid in sorted(wanted):
        try:
            definition = graph.get(f"/deviceManagement/configurationSettings/{sid}")
        except GraphError:
            continue
        for o in definition.get("options") or []:
            value = (o.get("optionValue") or {}).get("value")
            if o.get("itemId") and value is not None:
                options[o["itemId"].lower()] = value
    if not options:
        return
    for p in policies:
        for sid, vals in p.values.items():
            p.values[sid] = [options.get(v.lower(), v) if isinstance(v, str) else v for v in vals]


# ----------------------------------------------------------------- comparison


def _norm(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return str(value).strip().lower()


def value_matches(found: Any, expected: Any, setting_id: str = "") -> bool | None:
    """True/False when comparable, None when the shape can't be compared."""
    if isinstance(expected, dict) and isinstance(found, dict):
        # keys several rules add to (mount-controls, one media type each): the rule's keys must be there
        if not {k.lower() for k in expected} <= {k.lower() for k in found}:
            return False
        low = {k.lower(): v for k, v in found.items()}
        results = [value_matches(low[k.lower()], v) for k, v in expected.items()]
        return None if None in results else all(results)
    if isinstance(expected, list) and isinstance(found, list):
        # list keys collect items from several rules (DisabledSystemSettings, SkipSetupItems...):
        # a rule is met when its items are in the list, whatever else is there
        results = [any(value_matches(f, e) for f in found) for e in expected]
        return all(results)
    if isinstance(expected, (dict, list)) or isinstance(found, (dict, list)):
        return None
    if isinstance(found, str) and setting_id and found.lower().startswith(setting_id.lower() + "_"):
        found = found[len(setting_id) + 1 :]  # choice values are "<setting id>_<option>"
    f, e = _norm(found), _norm(expected)
    if f == e:
        return True
    if isinstance(expected, bool) and f in ("0", "1", "on", "off", "yes", "no"):
        return (f in ("1", "on", "yes")) == expected  # e.g. FileVault2 Enable "On" for mSCP's true
    return False


def _hits(policies: list[Policy], exp: Expected) -> list[tuple[Policy, Any]]:
    keys = [exp.setting_id] if exp.setting_id else []
    custom_key = f"{exp.payload_type.lower()}|{exp.key.lower()}"
    hits = []
    for p in policies:
        lookup = keys if p.kind == "settings_catalog" else [custom_key]
        for k in lookup:
            for v in p.values.get(k, []):
                hits.append((p, v))
    return hits


def rule_coverage(rule: Macsecurityrule, policies: list[Policy]) -> dict[str, Any]:
    """Check the rule's own form (DDM or MDM) first; if the tenant configures it only
    through the other form, report that instead and say which form matched."""
    results = []
    for form in forms(rule):
        res = _form_coverage(expected_settings(rule, form), policies)
        if res is None:
            continue
        res["matched_via"] = form
        if res["status"] != "not_configured" and not res["status"].startswith("not_configured"):
            return res
        results.append(res)
    return results[0] if results else {"status": "not_applicable"}


def _form_coverage(exps: list[Expected], policies: list[Policy]) -> dict[str, Any] | None:
    if not exps:
        return None
    settings, statuses = [], []
    for exp in exps:
        hits = _hits(policies, exp)
        found = []
        for p, v in hits:
            m = value_matches(v, exp.value, exp.setting_id if p.kind == "settings_catalog" else "")
            found.append({**p.ref(), "value": v, "matches": m})
        if not hits:
            st = "not_configured"
        elif any(f["matches"] is False for f in found):
            st = "conflict"
        elif len({f["name"] for f in found}) > 1:
            st = "duplicate"
        elif any(f["matches"] is None for f in found):
            st = "configured_unverified_value"
        else:
            st = "covered_assigned" if any(p.assignment["assigned"] for p, _ in hits) else "covered_unassigned"
        statuses.append(st)
        settings.append(
            {
                "setting": exp.setting_id or f"{exp.payload_type}:{exp.key}",
                "expected": exp.value,
                "in_settings_catalog": exp.in_catalog,
                "status": st,
                "found_in": found,
            }
        )
    # Worst status across the rule's settings wins.
    order = [
        "conflict",
        "duplicate",
        "configured_unverified_value",
        "not_configured",
        "covered_unassigned",
        "covered_assigned",
    ]
    status = min(statuses, key=order.index)
    if status == "not_configured" and any(s.startswith("covered") for s in statuses):
        status = "partial"
    if status == "not_configured" and not any(e.in_catalog for e in exps):
        status = "not_configured_custom_profile_only"
    return {"status": status, "settings": settings}


# ------------------------------------------------------- built-in compliance

# rule id -> (property, kind). Kinds: "true"; "one_of:<a>,<b>"; "min" (>= the
# baseline's value); "max" (<= it, 0 means not set); "max0" (<= it, 0 allowed).
# Password properties only count when the policy requires a password at all.
COMPLIANCE_CHECKS: dict[Platform, dict[str, tuple[str, str]]] = {
    Platform.MACOS: {
        "system_settings_filevault_enforce": ("storageRequireEncryption", "true"),
        "system_settings_firewall_enable": ("firewallEnabled", "true"),
        "system_settings_firewall_stealth_mode_enable": ("firewallEnableStealthMode", "true"),
        "os_sip_enable": ("systemIntegrityProtectionEnabled", "true"),
        "os_gatekeeper_enable": (
            "gatekeeperAllowedAppSource", "one_of:macAppStore,macAppStoreAndIdentifiedDevelopers"
        ),
        "pwpolicy_minimum_length_enforce": ("passwordMinimumLength", "min"),
        "pwpolicy_simple_sequence_disable": ("passwordBlockSimple", "true"),
        "pwpolicy_alpha_numeric_enforce": ("passwordRequiredType", "one_of:alphanumeric"),
        "pwpolicy_history_enforce": ("passwordPreviousPasswordBlockCount", "min"),
        "pwpolicy_max_lifetime_enforce": ("passwordExpirationDays", "max"),
    },
    Platform.IOS: {
        "pwpolicy_force_pin_enable": ("passcodeRequired", "true"),
        "pwpolicy_minimum_length_enforce": ("passcodeMinimumLength", "min"),
        "pwpolicy_simple_sequence_disable": ("passcodeBlockSimple", "true"),
        "pwpolicy_alpha_numeric_enforce": ("passcodeRequiredType", "one_of:alphanumeric"),
        "pwpolicy_history_enforce": ("passcodePreviousPasscodeBlockCount", "min"),
        "pwpolicy_max_inactivity_enforce": ("passcodeMinutesOfInactivityBeforeScreenTimeout", "max"),
        "pwpolicy_max_grace_period_enforce": ("passcodeMinutesOfInactivityBeforeLock", "max0"),
    },
}
PASSWORD_REQUIRED = {Platform.MACOS: "passwordRequired", Platform.IOS: "passcodeRequired"}


def compliance_value(props: dict, prop: str, kind: str, platform: Platform, odv: Any) -> tuple[bool, bool, Any]:
    """(is set, meets the baseline, value) for one compliance policy."""
    value = props.get(prop)
    pw = PASSWORD_REQUIRED[platform]
    if prop.startswith(("password", "passcode")) and prop != pw and not props.get(pw):
        return False, False, value
    if kind == "true":
        return bool(value), bool(value), value
    if kind.startswith("one_of:"):
        if value in (None, "", "notConfigured", "deviceDefault"):
            return False, False, value
        return True, value in kind[len("one_of:"):].split(","), value
    if value is None or (value == 0 and kind != "max0"):
        return False, False, value
    if odv is None:
        return True, True, value
    try:
        v, target = float(value), float(odv)
    except (TypeError, ValueError):
        return True, False, value
    return True, (v >= target if kind == "min" else v <= target), value


def custom_compliance_rules(policy: dict) -> list[dict]:
    """The rules JSON of a compliance policy's custom compliance script, if it has one."""
    script = policy.get("deviceCompliancePolicyScript") or {}
    content = script.get("rulesContent")
    if not content:
        return []
    try:
        data = json.loads(base64.b64decode(content))
    except Exception:  # noqa: BLE001 - a broken rules file shouldn't stop the check
        return []
    return [r for r in data.get("Rules", []) or [] if isinstance(r, dict) and r.get("SettingName")]


# Setting names in custom compliance scripts people already wrote. Our own generated
# scripts use the mSCP rule ID as the setting name, which always matches exactly.
SCRIPT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "os_sip_enable": ("sip", "systemintegrity"),
    "os_gatekeeper_enable": ("gatekeeper",),
    "system_settings_filevault_enforce": ("filevault",),
    "system_settings_firewall_enable": ("firewall",),
    "system_settings_firewall_stealth_mode_enable": ("stealth",),
}


def _script_matches(rule_id: str, setting_name: str) -> bool:
    name = setting_name.lower()
    if name == rule_id.lower():
        return True
    words = SCRIPT_KEYWORDS.get(rule_id, ())
    if rule_id == "system_settings_firewall_enable" and "stealth" in name:
        return False
    return any(w in name for w in words)


def _script_rule_meets(rule: dict) -> bool:
    """A boolean 'IsEquals true' rule, or an exact-ID rule we generated, counts as checking it."""
    op, operand = str(rule.get("Operator", "")).lower(), rule.get("Operand")
    if op == "isequals" and (operand is True or str(operand).lower() in ("true", "1", "pass")):
        return True
    return False


def rule_verification(
    rule_id: str, platform: Platform, odv: Any, compliance: list[Policy]
) -> dict[str, Any] | None:
    """Whether a compliance policy checks this rule, through a built-in setting or a custom
    compliance script. None when there's no built-in setting and no script checks it."""
    check = COMPLIANCE_CHECKS[platform].get(rule_id)
    found = []
    for p in compliance:
        if check:
            is_set, ok, value = compliance_value(p.props, check[0], check[1], platform, odv)
            if is_set:
                found.append({**p.ref(), "via": "built-in setting", "value": value,
                              "meets_baseline": ok, "_assigned": p.assignment["assigned"]})
        for r in p.props.get("_script_rules", []):
            if _script_matches(rule_id, str(r["SettingName"])):
                found.append({**p.ref(), "via": f"custom compliance script ({r['SettingName']})",
                              "value": f"{r.get('Operator')} {r.get('Operand')}",
                              "meets_baseline": _script_rule_meets(r), "_assigned": p.assignment["assigned"]})
    if not check and not found:
        return None
    if any(f["meets_baseline"] and f["_assigned"] for f in found):
        status = "verified_assigned"
    elif any(f["meets_baseline"] for f in found):
        status = "verified_unassigned"
    elif found:
        status = "compliance_different_value"
    else:
        status = "not_verified"
    for f in found:
        del f["_assigned"]
    out: dict[str, Any] = {"status": status, "found_in": found}
    if check:
        out["compliance_setting"] = check[0]
    if check and odv is not None and check[1] in ("min", "max", "max0"):
        out["baseline_value"] = odv
    return out
