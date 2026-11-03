"""Turn a baseline into Intune policies, written as local files for review.

Per mSCP section:

* one **Settings Catalog** policy with every rule the catalog can express
  (DDM declarations included, they are Settings Catalog settings too), and
* one **custom profile** (.mobileconfig) only for rules the catalog can't
  express.

Rules the tenant already configures are skipped and reported with the policy
that has them; rules configured with a different value are not generated
(that would create an Intune conflict) and are reported for fixing. Nothing
is sent to Intune here.
"""

from __future__ import annotations

import base64
import json
import plistlib
import re
import shutil
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import classify, coverage, requirements
from .catalog import SettingDefinitions, choice_item, kind, parent_of, required_children, simple_value
from .mapping import MCX, Expected, _ddm_leaves, expected_settings, forms, payload_leaves
from .platforms import Platform

if TYPE_CHECKING:
    from mscp.classes.baseline import Baseline
    from mscp.classes.macsecurityrule import Macsecurityrule

NAMESPACE = uuid.UUID("6f1d2c1e-6a43-4a43-9a8c-1f5b0b3e7a10")
SKIP = {"covered_assigned", "covered_unassigned"}
ATTENTION = {"conflict", "duplicate", "configured_unverified_value"}


def policy_name(prefix: str, platform: Platform, baseline: str, os_version: str, section: str, kind_: str) -> str:
    return f"{prefix} - {platform.mscp_os} - {baseline} {os_version} - {section} - {kind_}"


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")


class BuildError(Exception):
    pass


# --------------------------------------------------------------- tree building


@dataclass
class Node:
    d: dict
    item: str | None = None  # choice option ID
    items: list[str] | None = None  # choice collection option IDs
    simple: dict | None = None
    simples: list[dict] | None = None
    children: dict[str, Node] = field(default_factory=dict)

    def leaf_text(self) -> str | None:
        if self.item:
            return self.item[len(self.d["id"]) + 1 :] if self.item.lower().startswith(self.d["id"].lower() + "_") else self.item
        if self.simple is not None:
            return str(self.simple["value"])
        if self.items is not None:
            return ", ".join(self.items)
        if self.simples is not None:
            return ", ".join(str(s["value"]) for s in self.simples)
        return None


def _encode(node: Node, value: Any) -> None:
    k = kind(node.d)
    if k == "choicesetting":
        item = choice_item(node.d, value)
        if not item:
            raise BuildError(f"{node.d['id']}: no option for value {value!r}")
        if node.item and node.item != item:
            raise BuildError(f"{node.d['id']}: rules in this section want different values")
        node.item = item
    elif k == "choicesettingcollection":
        vals = value if isinstance(value, list) else [value]
        items = [choice_item(node.d, v) for v in vals]
        if None in items:
            raise BuildError(f"{node.d['id']}: no option for one of {vals!r}")
        node.items = items
    elif k == "simplesetting":
        sv = simple_value(node.d, value)
        if sv is None:
            raise BuildError(f"{node.d['id']}: value {value!r} doesn't fit")
        node.simple = sv
    elif k == "simplesettingcollection":
        vals = value if isinstance(value, list) else [value]
        svs = [simple_value(node.d, v) for v in vals]
        if None in svs:
            raise BuildError(f"{node.d['id']}: a value in {vals!r} doesn't fit")
        node.simples = svs
    else:
        raise BuildError(f"{node.d['id']}: a {k} setting can't take a plain value")


class Tree:
    """The Settings Catalog setting instances for one policy."""

    def __init__(self, defs: SettingDefinitions) -> None:
        self.defs = defs
        self.roots: dict[str, Node] = {}

    def chain(self, sid: str) -> list[tuple[dict, str | None]]:
        """Definitions from the root down to the setting. Each comes with the option it must
        be set to when it is a choice something below hangs under (else None)."""
        out: list[tuple[dict, str | None]] = []
        d = self.defs.get(sid)
        if d is None:
            raise BuildError(f"{sid} is not in the Settings Catalog")
        via = None
        seen = set()
        while d is not None:
            if d["id"] in seen:
                raise BuildError(f"{sid}: definition loop")
            seen.add(d["id"])
            pid, opt = parent_of(d)
            out.append((d, via))
            via = opt
            if not pid:
                break
            d = self.defs.get(pid)
            if d is None:
                raise BuildError(f"{sid}: parent {pid} not found")
        out.reverse()
        return out

    def _existing(self, chain: list[tuple[dict, str | None]]) -> list[Node | None]:
        level: dict[str, Node] | None = self.roots
        found: list[Node | None] = []
        for d, _ in chain:
            node = level.get(d["id"]) if level is not None else None
            found.append(node)
            level = node.children if node else None
        return found

    def check(self, leaves: list[tuple[str, Any]]) -> None:
        """Raise BuildError if any leaf can't be expressed or clashes with what's already
        in this policy; changes nothing."""
        for sid, value in leaves:
            chain = self.chain(sid)
            probe = Node(chain[-1][0])
            _encode(probe, value)
            existing = self._existing(chain)
            leaf = existing[-1]
            if leaf and leaf.leaf_text() is not None and probe.leaf_text() is not None \
                    and (leaf.item, leaf.items, leaf.simple, leaf.simples) != \
                    (probe.item, probe.items, probe.simple, probe.simples):
                # choice, integer, string or collection: never overwrite another rule's value
                raise BuildError(f"{sid}: another rule in this section sets a different value")
            for (d, opt), node in zip(chain[:-1], existing[:-1]):
                if opt and node and node.item and node.item != opt:
                    raise BuildError(f"{d['id']} must be {opt} for {sid}")

    def add(self, sid: str, value: Any) -> None:
        chain = self.chain(sid)
        level = self.roots
        parent: Node | None = None
        for d, _ in chain:
            node = level.get(d["id"])
            if node is None:
                node = level[d["id"]] = Node(d)
            parent, level = node, node.children
        # choices the path hangs under must be set to the right option
        for i, (d, opt) in enumerate(chain[:-1]):
            if opt:
                node = self._find(chain[: i + 1])
                if node.item and node.item != opt:
                    raise BuildError(f"{d['id']} must be {opt} for {sid}")
                node.item = opt
        _encode(parent, value)

    def _find(self, chain: list[tuple[dict, str | None]]) -> Node:
        level, node = self.roots, None
        for d, _ in chain:
            node = level[d["id"]]
            level = node.children
        return node

    def fill_required(self, value_for) -> list[dict]:
        """Add settings Intune requires next to the ones we set (e.g. EnableFirewall)."""
        added: list[dict] = []

        def walk(node: Node) -> None:
            for child_id in required_children(node.d):
                if child_id in node.children:
                    continue
                d = self.defs.get(child_id)
                if d is None or kind(d) not in ("choicesetting", "simplesetting"):
                    continue
                value, source = value_for(child_id, d)
                if value is None:
                    continue
                child = Node(d)
                try:
                    _encode(child, value)
                except BuildError:
                    continue
                node.children[child_id] = child
                entry = {"setting": child_id, "value": child.leaf_text(), "source": source}
                if source == "Intune default" and not child.leaf_text():
                    entry["needs_value"] = True
                added.append(entry)
            for c in list(node.children.values()):
                walk(c)

        for root in self.roots.values():
            walk(root)
        return added

    def instances(self) -> list[dict]:
        return [
            {"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting", "settingInstance": _instance(n)}
            for n in self.roots.values()
        ]

    def leaves(self) -> list[str]:
        out: list[str] = []

        def walk(n: Node) -> None:
            text = n.leaf_text()
            if text is not None:
                out.append(f"{n.d['id']} = {text}")
            for c in n.children.values():
                walk(c)

        for r in self.roots.values():
            walk(r)
        return out


def _instance(n: Node) -> dict:
    k, sid = kind(n.d), n.d["id"]
    children = [_instance(c) for c in n.children.values()]
    t = "#microsoft.graph.deviceManagementConfiguration"
    if k == "settinggroupcollection":
        return {"@odata.type": t + "GroupSettingCollectionInstance", "settingDefinitionId": sid,
                "groupSettingCollectionValue": [{"children": children}]}
    if k == "settinggroup":
        return {"@odata.type": t + "GroupSettingInstance", "settingDefinitionId": sid,
                "groupSettingValue": {"children": children}}
    if k == "choicesetting":
        item = n.item or n.d.get("defaultOptionId")
        return {"@odata.type": t + "ChoiceSettingInstance", "settingDefinitionId": sid,
                "choiceSettingValue": {"value": item, "children": children}}
    if k == "choicesettingcollection":
        return {"@odata.type": t + "ChoiceSettingCollectionInstance", "settingDefinitionId": sid,
                "choiceSettingCollectionValue": [{"value": i, "children": []} for i in n.items or []]}
    if k == "simplesettingcollection":
        return {"@odata.type": t + "SimpleSettingCollectionInstance", "settingDefinitionId": sid,
                "simpleSettingCollectionValue": n.simples or []}
    return {"@odata.type": t + "SimpleSettingInstance", "settingDefinitionId": sid, "simpleSettingValue": n.simple}


# ------------------------------------------------------------------ planning


def _leaves(exps: list[Expected]) -> list[tuple[str, Any]]:
    out = []
    for e in exps:
        if isinstance(e.value, dict) and e.value:
            out.extend((sid, v) for sid, _, v in _ddm_leaves(e.setting_id, e.key, e.value))
        else:
            out.append((e.setting_id, e.value))
    return out


@dataclass
class SectionOut:
    section: str
    tree: Tree
    catalog_rules: list[str] = field(default_factory=list)
    custom: dict[str, dict[str, Any]] = field(default_factory=lambda: defaultdict(dict))
    custom_rules: list[str] = field(default_factory=list)
    custom_keys: dict[tuple[str, str], str] = field(default_factory=dict)  # (payload type, key) -> rule
    list_rules: dict[tuple[str, str], list[str]] = field(default_factory=dict)  # list key -> rules adding to it
    catalog_fallbacks: dict[str, str] = field(default_factory=dict)  # rule -> why its catalog settings didn't fit
    titles: dict[str, str] = field(default_factory=dict)  # rule -> mSCP title
    placed: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # rule -> (payload type, key) it sets


def build(
    base: Baseline,
    platform: Platform,
    defs: SettingDefinitions,
    scan: coverage.TenantScan | None,
    sections: list[str] | None = None,
    required_values: dict[str, Any] | None = None,
    *,
    os_version: str | None = None,
    unsupervised: bool = False,
) -> dict[str, Any]:
    chosen = {k.lower(): v for k, v in (required_values or {}).items()}
    skipped, attention, undeliverable = [], [], []
    switched: list[dict[str, Any]] = []
    not_policy: dict[str, list[str]] = defaultdict(list)
    outs: list[SectionOut] = []
    rules_by_id = {r.rule_id: r for p in base.profile for r in p.rules}

    # Values the baseline itself wants, for settings Intune requires alongside ours.
    wanted: dict[str, Any] = {}
    for p in base.profile:
        for r in p.rules:
            for form in forms(r) if r.ddm_info or r.mobileconfig_info else []:
                for sid, v in _leaves(expected_settings(r, form)):
                    if sid:
                        wanted.setdefault(sid.lower(), v)
    tenant_values: dict[str, Any] = {}
    for pol in scan.config if scan else []:
        for sid, vals in pol.values.items():
            if vals and sid not in tenant_values:
                tenant_values[sid.lower()] = (vals[0], pol.name)

    def value_for(sid: str, d: dict) -> tuple[Any, str]:
        # The baseline's own value wins: a rule elsewhere in this baseline sets it, and a different
        # value here would conflict with that policy. Saved choices fill only what the baseline leaves open.
        if sid.lower() in wanted:
            also = tenant_values.get(sid.lower())
            source = "baseline" + (f" (also set in '{also[1]}')" if also else "")
            mine = chosen.get(sid.lower())
            if mine is not None and str(mine) != str(wanted[sid.lower()]):
                source += f"; your saved value '{mine}' applies only to baselines that don't set it"
            return wanted[sid.lower()], source
        if sid.lower() in chosen:
            return chosen[sid.lower()], "your choice"
        if sid.lower() in tenant_values:
            v, pol = tenant_values[sid.lower()]
            return v, f"same as existing policy '{pol}'"
        if d.get("defaultOptionId"):
            return d["defaultOptionId"], "Intune default"
        return (d.get("defaultValue") or {}).get("value"), "Intune default"

    for prof in base.profile:
        if sections and prof.section not in sections:
            continue
        out = SectionOut(prof.section, Tree(defs))
        for rule in prof.rules:
            how = classify.delivery(rule)
            if how not in ("ddm", "profile"):
                not_policy[how].append(rule.rule_id)
                continue
            exps: list[Expected] | None = None
            if scan is not None:
                cov = coverage.rule_coverage(rule, scan.config)
                st = cov["status"]
                where = sorted({f["name"] for s in cov.get("settings", []) for f in s["found_in"]})
                if st in SKIP:
                    skipped.append({"rule": rule.rule_id, "status": st, "policies": where})
                    continue
                if st in ATTENTION:
                    attention.append({"rule": rule.rule_id, "status": st, "policies": where,
                                      "why": "Not generated: fix the existing policy instead, or Intune reports a conflict."})
                    continue
                if st == "partial":
                    missing = {s["setting"] for s in cov["settings"] if s["status"] == "not_configured"}
                    exps = [e for e in expected_settings(rule, cov["matched_via"]) if e.setting_id in missing]
                    skipped.append({"rule": rule.rule_id, "status": "partial",
                                    "policies": where, "generating": sorted(missing)})
            placed = False
            if unsupervised and exps is None and os_version:
                alt = unsupervised_alternative(rule, platform, os_version)
                if alt:
                    before = out.catalog_fallbacks.get(rule.rule_id)
                    placed = _place_catalog(out, rule, None, [expected_settings(rule, "mdm")]) or \
                        _place_custom(out, rule, None)[0]
                    if placed:
                        switched.append({"rule": rule.rule_id, "section": prof.section, **alt})
                    elif before is None:
                        out.catalog_fallbacks.pop(rule.rule_id, None)
            if not placed:
                placed = _place_catalog(out, rule, exps)
            why = None
            clash = out.catalog_fallbacks.get(rule.rule_id, "")
            if not placed and "different value" in clash:
                # two rules of this baseline want different values for one setting (mSCP lists
                # both, e.g. smart card trust high and moderate): delivering the second one through
                # a custom profile would give the Mac two values, so report it instead
                others = [r for r in out.catalog_rules if any(
                    e.setting_id and clash.startswith(e.setting_id) for f in forms(rules_by_id[r])
                    for e in expected_settings(rules_by_id[r], f))]
                why = (f"Conflicts with {', '.join(others) or 'another rule'} in this baseline ({clash}); "
                       "mSCP lists both. Tailor one of them out.")
                out.catalog_fallbacks.pop(rule.rule_id, None)
            elif not placed:
                placed, why = _place_custom(out, rule, exps)
            if not placed:
                if not why and rule.ddm_info and not rule.mobileconfig_info:
                    why = (f"Declarative (DDM) only: {rule.ddm_info.get('declarationtype', 'its declaration')} isn't "
                           "in the Settings Catalog, and Intune can't send custom declarations.")
                    if (rule.check or "").strip():
                        why += (" Compliance checks it with mSCP's check"
                                + (" and remediation enforces it with mSCP's fix." if (rule.fix or "").strip() else "."))
                undeliverable.append({"rule": rule.rule_id, "why": why or
                                      "Not in the Settings Catalog and has no configuration profile payload in mSCP."})
        outs.append(out)

    merged = _merge_lists_across_sections(outs)
    heads_up = []
    for out in outs:
        for rid, keys in out.placed.items():
            for ptype in dict.fromkeys(pt for pt, _ in keys):
                if ptype in HEADS_UP:
                    heads_up.append({"rule": rid, "section": out.section, "payload": ptype, "note": HEADS_UP[ptype]})
            for ptype, key in keys:  # mSCP placeholders, e.g. VPNUUID = "VPNUUID"
                v = out.custom.get(ptype, {}).get(key)
                if isinstance(v, str) and v == key:
                    heads_up.append({"rule": rid, "section": out.section, "payload": ptype,
                                     "note": f"{key} is mSCP's placeholder '{v}'; replace it with your own value "
                                             "(e.g. the PayloadUUID of your VPN payload) before pushing."})
    heads_up += sign_in_heads_up(outs, rules_by_id, platform)
    heads_up += key_issue_heads_up(outs)
    return {"sections": outs, "skipped": skipped, "attention": attention,
            "undeliverable": undeliverable, "not_policy": not_policy, "value_for": value_for,
            "merged_lists": merged, "baseline_sets": set(wanted), "switched_to_profile": switched,
            "heads_up": heads_up}


# mSCP rule payloads that don't do what the rule says (checked against Apple's schema). Generated as
# mSCP has them, with a heads up.
MSCP_KEY_ISSUES = {
    ("pwpolicy_account_lockout_timeout_enforce", "com.apple.configuration.passcode.settings",
     "MaximumGracePeriodInMinutes"): (
        "mSCP's declaration for 'lockout time' sets MaximumGracePeriodInMinutes, which per Apple is how long a "
        "locked screen can be unlocked without the password, not how long an account stays locked after failed "
        "attempts (that is FailedAttemptsResetInMinutes). Its MDM payload uses the right key "
        "(minutesUntilFailedLoginReset); the unsupervised variant (unsupervised=true) uses it; or tailor the value."
    ),
}


def key_issue_heads_up(outs: list[SectionOut]) -> list[dict]:
    return [{"rule": rid, "section": out.section, "payload": ptype, "kind": "mscp_issue",
             "note": MSCP_KEY_ISSUES[(rid, ptype, key)]}
            for out in outs for rid, keys in out.placed.items() for ptype, key in keys
            if (rid, ptype, key) in MSCP_KEY_ISSUES]


# Passcode keys (MDM and DDM spelling, lowercased) -> what they do to signing in.
_PASSCODE = {
    "maxfailedattempts": "attempts", "maximumfailedattempts": "attempts",
    "minutesuntilfailedloginreset": "reset", "failedattemptsresetinminutes": "reset",
    "minlength": "length", "minimumlength": "length",
    "pinhistory": "history", "passcodereuselimit": "history",
    "maxpinageindays": "age", "maximumpasscodeageindays": "age",
    "changeatnextauth": "change",
}


def sign_in_heads_up(outs: list[SectionOut], rules: dict[str, Macsecurityrule], platform: Platform) -> list[dict]:
    """Rules that change how people sign in, one note per section: lockout (on iOS: erase), length,
    login window asking for the account name. Easy to lock yourself out of a test device with."""
    out = []
    for sec in outs:
        found: dict[str, Any] = {}
        pw_rules = []
        for rid, keys in sec.placed.items():
            rule = rules.get(rid)
            if rule is None:
                continue
            values = {e.key.lower(): e.value for f in forms(rule) for e in expected_settings(rule, f)}
            for _, key in keys:
                what = _PASSCODE.get(key.lower().split(".")[-1])
                if what:
                    found[what] = values.get(key.lower())
                    if rid not in pw_rules:
                        pw_rules.append(rid)
            if rid == "system_settings_loginwindow_prompt_username_password_enforce":
                out.append({"rule": rid, "section": sec.section, "payload": "com.apple.loginwindow",
                            "kind": "sign_in",
                            "note": "The login window shows name and password fields instead of a user list: people "
                                    "type their account name (the short name, e.g. 'jdoe', or the full name) as well "
                                    "as the password. Tell users before it reaches their Macs."})
        if not pw_rules:
            continue
        bits = []
        pw = "passcode" if platform is Platform.IOS else "password"
        if found.get("attempts"):
            if platform is Platform.IOS:
                bits.append(f"after {found['attempts']} wrong passcodes the device is ERASED")
            else:
                bits.append(f"after {found['attempts']} failed sign-ins the account is locked"
                            + (f" for {found['reset']} minutes (even the right password is refused)"
                               if found.get("reset") else ""))
        if found.get("length"):
            bits.append(f"{pw}s need at least {found['length']} characters; a shorter existing one has to be "
                        "changed at the next " + ("unlock" if platform is Platform.IOS else "sign-in"))
        if found.get("history"):
            bits.append(f"the last {found['history']} {pw}s can't be reused")
        if found.get("age"):
            bits.append(f"{pw}s expire after {found['age']} days")
        if found.get("change"):
            bits.append(f"users must change their {pw} at the next sign-in")
        out.append({"rule": ", ".join(pw_rules), "section": sec.section, "payload": "passcode", "kind": "sign_in",
                    "note": "Changes signing in: " + "; ".join(bits) + ". Test on a device you can recover "
                            + ("(a backup you can restore)." if platform is Platform.IOS else
                               "(FileVault recovery key escrowed in Intune, or a VM snapshot).")})
    return out


# Payloads mSCP sends with only the key a rule needs, but which define a whole account on the
# device. Generated as mSCP has them; the person is told what else the payload needs.
HEADS_UP = {
    "com.apple.mail.managed": (
        "com.apple.mail.managed defines a complete mail account. mSCP only sets the rule's key plus "
        "EmailAccountType = EmailTypeIMAP, so on its own the device gets an IMAP account with no server or user. "
        "Before pushing, add the account details (EmailAccountDescription, IncomingMailServerHostName, "
        "IncomingMailServerUsername, OutgoingMailServerHostName, ...) or move the key into the profile that already "
        "configures this mail account. Exchange accounts (com.apple.eas.account) have their own equivalent key."
    ),
    "com.apple.eas.account": (
        "com.apple.eas.account defines a complete Exchange ActiveSync account. Set the rule's key on the profile "
        "that configures the account (Host, user, authentication), not in a profile of its own."
    ),
}


def unsupervised_alternative(rule: Macsecurityrule, platform: Platform, os_version: str) -> dict[str, Any] | None:
    """The rule's MDM payload, when its declaration only applies to supervised devices and the payload
    doesn't (passcode on user-enrolled Macs, intelligence restrictions on 26.0-26.3). None otherwise."""
    if not (rule.ddm_info and rule.mobileconfig_info) or forms(rule)[0] != "ddm":
        return None
    ddm = [requirements.check(platform, os_version, e.payload_type, e.key) or {}
           for e in expected_settings(rule, "ddm")]
    if not any(n.get("supervised") for n in ddm):
        return None
    mdm = [(e, requirements.check(platform, os_version, e.payload_type, e.key) or {})
           for e in expected_settings(rule, "mdm")]
    if not mdm or any(n.get(f) for _, n in mdm for f in ("supervised", "removed_in", "not_available")):
        return None
    instead = sorted({f"{e.payload_type} {e.key}" for e, _ in mdm})
    deprecated = sorted({n["deprecated_in"] for _, n in mdm if n.get("deprecated_in")}, key=requirements._v)
    min_os = sorted({n["min_os"] for _, n in mdm if n.get("min_os")}, key=requirements._v)
    return {"declaration": rule.ddm_info.get("declarationtype", ""), "instead": instead,
            **({"deprecated_in": deprecated[-1]} if deprecated else {}),
            **({"min_os": min_os[-1]} if min_os else {})}


def _add_items(current: list, new: list) -> list:
    out = list(current)
    for item in new:
        if item not in out:
            out.append(item)
    return out


def _combine(current: Any, new: Any) -> Any:
    """Values several rules add to: lists collect items, dictionaries collect keys (e.g.
    mount-controls, one media type per rule). None when they can't be combined."""
    if isinstance(current, list) and isinstance(new, list):
        return _add_items(current, new)
    if isinstance(current, dict) and isinstance(new, dict):
        out = dict(current)
        for k, v in new.items():
            if k in out and out[k] != v:
                merged = _combine(out[k], v)
                if merged is None:
                    return None
                out[k] = merged
            else:
                out[k] = v
        return out
    return None


def _merge_lists_across_sections(outs: list[SectionOut]) -> list[dict[str, Any]]:
    """A list key (DisabledSystemSettings, SkipSetupItems...) set by rules in several sections goes
    in one profile only, the first section's, with every rule's items: two profiles setting the same
    key don't combine on the Mac, one wins. mSCP combines list values the same way."""
    where: dict[tuple[str, str], list[SectionOut]] = defaultdict(list)
    for out in outs:
        for ptype, keys in out.custom.items():
            for k, v in keys.items():
                if isinstance(v, (list, dict)):
                    where[(ptype, k)].append(out)
    merged = []
    for (ptype, k), holders in where.items():
        if len(holders) < 2:
            continue
        home = holders[0]
        values = [h.custom[ptype][k] for h in holders]
        combined = values[0]
        for v in values[1:]:
            combined = _combine(combined, v) if combined is not None else None
        if combined is None:
            continue  # can't be combined: the self-test reports the key in two profiles
        home.custom[ptype][k] = combined
        for other in holders[1:]:
            other.custom[ptype].pop(k)
            if not other.custom[ptype]:
                del other.custom[ptype]
            rules = other.list_rules.pop((ptype, k), [])
            other.custom_keys.pop((ptype, k), None)
            still = {r for (pt, kk), r in other.custom_keys.items()} | {
                r for rs in other.list_rules.values() for r in rs}
            for r in rules:
                home.list_rules.setdefault((ptype, k), []).append(r)
                home.titles[r] = other.titles.get(r, r)
                home.placed.setdefault(r, other.placed.get(r, []))
                if r not in home.custom_rules:
                    home.custom_rules.append(r)
                if r not in still and r in other.custom_rules:
                    other.custom_rules.remove(r)
        merged.append({"payload": ptype, "key": k, "section": home.section,
                       "rules": home.list_rules.get((ptype, k), []), "value": home.custom[ptype][k]})
    return merged


def _place_catalog(out: SectionOut, rule: Macsecurityrule, exps: list[Expected] | None,
                   candidates: list[list[Expected]] | None = None) -> bool:
    if candidates is None:
        candidates = [exps] if exps is not None else [expected_settings(rule, f) for f in forms(rule)]
    for cand in candidates:
        if not cand or not all(e.in_catalog and e.setting_id for e in cand):
            continue
        leaves = _leaves(cand)
        try:
            out.tree.check(leaves)
            for sid, v in leaves:
                out.tree.add(sid, v)
        except BuildError as e:
            out.catalog_fallbacks.setdefault(rule.rule_id, str(e))
            continue
        out.catalog_fallbacks.pop(rule.rule_id, None)
        out.catalog_rules.append(rule.rule_id)
        out.titles[rule.rule_id] = _title(rule)
        out.placed[rule.rule_id] = [(e.payload_type, e.key) for e in cand]
        return True
    return False


def _place_custom(out: SectionOut, rule: Macsecurityrule, exps: list[Expected] | None) -> tuple[bool, str | None]:
    if not rule.mobileconfig_info:
        return False, None
    keep = {(e.payload_type, e.key) for e in exps} if exps is not None else None
    picked = [(ptype, k, v) for ptype, k, v in payload_leaves(rule) if keep is None or (ptype, k) in keep]
    if not picked:
        return False, None
    for ptype, k, v in picked:
        cur = out.custom[ptype].get(k)
        if k in out.custom[ptype] and cur != v and _combine(cur, v) is None:
            other = out.custom_keys.get((ptype, k), "another rule")
            return False, (f"{ptype} {k} = {v!r} conflicts with {cur!r} from {other} in the same baseline; "
                           "one profile key can hold one value.")
    for ptype, k, v in picked:
        if isinstance(v, (list, dict)):  # collect every rule's items/keys (lists as mSCP does)
            cur = out.custom[ptype].get(k)
            out.custom[ptype][k] = v if cur is None else _combine(cur, v)
            out.list_rules.setdefault((ptype, k), []).append(rule.rule_id)
        else:
            out.custom[ptype][k] = v
        out.custom_keys.setdefault((ptype, k), rule.rule_id)
    out.custom_rules.append(rule.rule_id)
    out.titles[rule.rule_id] = _title(rule)
    out.placed[rule.rule_id] = [(ptype, k) for ptype, k, _ in picked]
    return True, None


def _title(rule: Macsecurityrule) -> str:
    return " ".join(str(rule.title or "").split())


# ------------------------------------------------------------------- writing


def _comment(text: str) -> str:
    """An XML comment; '--' isn't allowed inside one."""
    return "<!-- " + " ".join(text.replace("--", "-").split()) + " -->"


def _fragment(key: str, value: Any, depth: int) -> list[str]:
    """The <key>/<value> lines plistlib writes for one entry, indented to ``depth`` tabs."""
    xml = plistlib.dumps({key: value}).decode()
    inner = xml[xml.index("<dict>") + len("<dict>"): xml.rindex("</dict>")].strip("\n")
    # Only element lines start with a tab; continuation lines of a multi-line string are
    # part of the value and must stay exactly as they are.
    return [("\t" * (depth - 1) + line) if line.startswith("\t") else line for line in inner.split("\n")]


def mobileconfig(
    name: str,
    description: str,
    payloads: dict[str, dict[str, Any]],
    key_rules: dict[tuple[str, str], str] | None = None,
    titles: dict[str, str] | None = None,
    header: str | None = None,
    payload_notes: dict[str, str] | None = None,
) -> bytes:
    """A .mobileconfig with XML comments marking where each payload starts and ends and which
    rule each key comes from. Comments are ignored by macOS and by plist parsers."""
    key_rules, titles = key_rules or {}, titles or {}
    top = str(uuid.uuid5(NAMESPACE, name)).upper()
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
    ]
    if header:
        lines.append("\t" + _comment(header))
    lines += ["\t<key>PayloadContent</key>", "\t<array>"]
    for ptype, keys in sorted(payloads.items()):
        puuid = str(uuid.uuid5(NAMESPACE, f"{name}|{ptype}")).upper()
        rules = list(dict.fromkeys(key_rules.get((ptype, k), "") for k in keys))
        rules = [r for r in rules if r]
        # Shown on the Mac (System Settings > Device Management): plain titles, no rule IDs.
        pdesc = "\n".join(dict.fromkeys(titles[r] for r in rules if titles.get(r)))
        lines.append("\t\t" + _comment(f"===== BEGIN payload {ptype} ({len(keys)} keys from {len(rules)} rules) ====="))
        if (payload_notes or {}).get(ptype):
            lines.append("\t\t" + _comment("HEADS UP: " + payload_notes[ptype]))
        lines.append("\t\t<dict>")
        mcx_domain = ptype[len(MCX) + 1:] if ptype.startswith(MCX + "/") else None
        depth = 3
        if mcx_domain:
            # Managed Client preferences (as mSCP writes them): the keys go in
            # PayloadContent -> domain -> Forced -> mcx_preference_settings
            lines += ["\t\t\t<key>PayloadContent</key>", "\t\t\t<dict>"]
            lines += _fragment(mcx_domain, {}, 4)[:1] + ["\t\t\t\t<dict>", "\t\t\t\t\t<key>Forced</key>",
                                                          "\t\t\t\t\t<array>", "\t\t\t\t\t\t<dict>",
                                                          "\t\t\t\t\t\t\t<key>mcx_preference_settings</key>",
                                                          "\t\t\t\t\t\t\t<dict>"]
            depth = 8
        # keys grouped by the rule that needs them, each group labelled
        by_rule: dict[str, list[str]] = defaultdict(list)
        for k in keys:
            by_rule[key_rules.get((ptype, k), "")].append(k)
        for rule_id, rule_keys in by_rule.items():
            if rule_id:
                lines.append("\t" * depth + _comment(f"{rule_id} - {titles.get(rule_id, '')}"))
            for k in rule_keys:
                lines += _fragment(k, keys[k], depth)
        if mcx_domain:
            lines += ["\t\t\t\t\t\t\t</dict>", "\t\t\t\t\t\t</dict>", "\t\t\t\t\t</array>",
                      "\t\t\t\t</dict>", "\t\t\t</dict>"]
        lines.append("\t\t\t" + _comment("payload metadata"))
        real_type = MCX if mcx_domain else ptype
        meta = {
            "PayloadDescription": pdesc or ptype,
            "PayloadDisplayName": ptype,
            "PayloadIdentifier": f"{real_type}.{puuid}",
            "PayloadType": real_type,
            "PayloadUUID": puuid,
            "PayloadVersion": 1,
        }
        for k, v in meta.items():
            lines += _fragment(k, v, 3)
        lines.append("\t\t</dict>")
        lines.append("\t\t" + _comment(f"===== END payload {ptype} ====="))
    lines.append("\t</array>")
    for k, v in {
        "PayloadDescription": description,
        "PayloadDisplayName": name,
        "PayloadIdentifier": f"com.apple-intune-baseline.{top}",
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": top,
        "PayloadVersion": 1,
    }.items():
        lines += _fragment(k, v, 1)
    lines += ["</dict>", "</plist>", ""]
    return "\n".join(lines).encode("utf-8")


DESCRIPTION_LIMIT = 1000  # kept within what both policy types accept


def _description(source: str, baseline: str, section: str, rules: list[str], titles: dict[str, str],
                 limit: int | None = DESCRIPTION_LIMIT, more_hint: str = "", note: str = "") -> str:
    head = [
        f"Generated by apple-intune-baseline from mSCP {source}",
        f"Baseline: {baseline}",
        f"Section: {section}",
        *([note] if note else []),
        "Rules:",
    ]
    lines = [f"{r} - {titles[r]}" if titles.get(r) else r for r in rules]
    text = "\n".join(head + lines)
    if limit is None or len(text) <= limit:
        return text
    kept: list[str] = []
    for i, line in enumerate(lines):
        tail = f"...and {len(lines) - i - 1} more{more_hint}"
        if len("\n".join(head + kept + [line, tail])) > limit:
            break
        kept.append(line)
    rest = len(lines) - len(kept)
    return "\n".join(head + kept + [f"...and {rest} more{more_hint}"])


def write(
    result: dict[str, Any],
    out_dir: Path,
    *,
    prefix: str,
    platform: Platform,
    baseline_display: str,
    baseline_name: str,
    os_version: str,
    mscp_version: str,
    name_os: str | None = None,
    variant_note: str = "",
) -> list[dict[str, Any]]:
    """``name_os`` is the OS part of the names (e.g. '26.0 Unsupervised'); ``os_version`` the real one."""
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    policies = []

    def needs(sec: SectionOut, rules: list[str], name: str) -> tuple[list[dict[str, Any]], str]:
        reqs = requirements.for_rules(platform, os_version, {r: sec.placed.get(r, []) for r in rules},
                                      {r: name for r in rules})
        return reqs, "\n".join(x for x in (variant_note, _requirement_note(platform, reqs)) if x)

    for sec in result["sections"]:
        if sec.catalog_rules:
            added = sec.tree.fill_required(result["value_for"])
            name = policy_name(prefix, platform, baseline_display, name_os or os_version, sec.section, "Settings Catalog")
            reqs, note = needs(sec, sec.catalog_rules, name)
            body = {
                "name": name,
                "description": _description(mscp_version, baseline_name, sec.section, sec.catalog_rules,
                                            sec.titles, more_hint=" (each setting is listed in the policy)",
                                            note=note),
                "platforms": platform.mscp_os,
                "technologies": "mdm,appleRemoteManagement",
                "roleScopeTagIds": ["0"],
                "settings": sec.tree.instances(),
            }
            f = out_dir / f"{slug(name)}.json"
            f.write_text(json.dumps(body, indent=2), encoding="utf-8")
            policies.append({"name": name, "type": "settings_catalog", "file": f.name,
                             "rules": sec.catalog_rules, "settings": sec.tree.leaves(),
                             **({"added_because_intune_requires": added} if added else {}),
                             **({"device_requirements": reqs} if reqs else {})})
        if sec.custom_rules:
            name = policy_name(prefix, platform, baseline_display, name_os or os_version, sec.section, "Custom")
            reqs, note = needs(sec, sec.custom_rules, name)
            desc = _description(mscp_version, baseline_name, sec.section, sec.custom_rules, sec.titles,
                                more_hint=" (full list in the profile's own description and comments)", note=note)
            full = _description(mscp_version, baseline_name, sec.section, sec.custom_rules, sec.titles, limit=None,
                                note=note)
            labels = {**sec.custom_keys, **{k: ", ".join(rs) for k, rs in sec.list_rules.items()}}
            plist = mobileconfig(name, full, sec.custom, labels, sec.titles,
                                 header=f"{name} | generated by apple-intune-baseline from mSCP {mscp_version}",
                                 payload_notes={pt: HEADS_UP[pt] for pt in sec.custom if pt in HEADS_UP})
            mc = out_dir / f"{slug(name)}.mobileconfig"
            mc.write_bytes(plist)
            body = {"@odata.type": platform.custom_profile_type, "displayName": name, "description": desc,
                    "payloadName": name, "payloadFileName": mc.name,
                    "payload": base64.b64encode(plist).decode()}
            if platform is Platform.MACOS:
                body["deploymentChannel"] = "deviceChannel"
            f = out_dir / f"{slug(name)}.json"
            f.write_text(json.dumps(body, indent=2), encoding="utf-8")
            policies.append({"name": name, "type": "custom_profile", "file": f.name, "mobileconfig": mc.name,
                             "rules": sec.custom_rules,
                             "settings": [f"{p}: {k} = {v}" for p, ks in sorted(sec.custom.items()) for k, v in ks.items()],
                             **({"device_requirements": reqs} if reqs else {})})
    return policies


def _requirement_note(platform: Platform, reqs: list[dict[str, Any]]) -> str:
    """One line for the policy description, so whoever sees 'Not applicable' in Intune knows why."""
    if not reqs:
        return ""
    os_ = platform.mscp_os
    parts = []
    mins = sorted({r["min_os"] for r in reqs if r.get("min_os")}, key=requirements._v)
    for v in mins:
        n = sum(1 for r in reqs if r.get("min_os") == v)
        parts.append(f"{n} rule(s) need {os_} {v}+")
    sup = sum(1 for r in reqs if r.get("supervised"))
    if sup:
        parts.append(f"{sup} rule(s) need a supervised {'Mac' if platform is Platform.MACOS else 'device'}")
    gone = sum(1 for r in reqs if r.get("not_available") or r.get("removed_in"))
    if gone:
        parts.append(f"{gone} rule(s) not supported on {os_}")
    if not parts:  # only deprecations: still applies, nothing to warn about here
        return ""
    return "Device requirements: " + "; ".join(parts) + " (otherwise 'Not applicable')"

