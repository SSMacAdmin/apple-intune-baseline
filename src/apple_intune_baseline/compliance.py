"""Selective custom compliance, built from mSCP's own checks.

Per mSCP section, one macOS compliance policy that can hold both:

* **Built-in settings** (FileVault, Firewall, Gatekeeper, SIP, password rules)
  for rules Intune can check natively. These replace a script check.
* **One discovery script + rules JSON** for the script rules left after the
  selection filters (see the design doc):

  - already verified in the tenant (built-in setting or a custom script that
    checks the rule) -> skipped, with the policy that does it
  - Intune has a built-in setting for it -> built-in, not scripted
  - reads the logged-in user's settings ($CURRENT_USER) -> left out by default:
    the script runs as root and the answer depends on who used the Mac last
  - sections in ``merge`` (default: Auditing) -> one setting per section that
    lists the failing rules, instead of one setting per rule

The script runs mSCP's ``check`` text unchanged in zsh (what mSCP writes and
tests them for) and compares the output with ``result_value`` as text, exactly
like mSCP's compliance script. Intune wants a bash shebang, so a bash wrapper
hands the checks to zsh. The script only reads; it never fixes anything.

Setting names are the mSCP rule IDs, so the coverage check matches them exactly.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .mapping import ddm_not_in_catalog
from . import classify, coverage
from .platforms import Platform

if TYPE_CHECKING:
    from mscp.classes.baseline import Baseline
    from mscp.classes.macsecurityrule import Macsecurityrule

DEFAULT_MERGE = ["Auditing"]
DEFAULT_MORE_INFO = "https://github.com/usnistgov/macos_security"
NOT_SCRIPTABLE_TAGS = {"permanent", "inherent", "n_a", "not_applicable", "manual"}


def setting_for_section(section: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", section).strip("_").lower() + "_failed_checks"


@dataclass
class SectionPlan:
    section: str
    scripted: list[Any] = field(default_factory=list)  # rules with their own setting
    merged: list[Any] = field(default_factory=list)  # rules folded into one section setting
    builtin: dict[str, Any] = field(default_factory=dict)  # compliance policy properties
    builtin_rules: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not (self.scripted or self.merged or self.builtin)


def _per_user(rule: Macsecurityrule) -> bool:
    return "CURRENT_USER" in (rule.check or "") or "CURR_USER_UID" in (rule.check or "")


# Ranges Graph accepts for built-in compliance properties (microsoft.graph.macOSCompliancePolicy).
# A baseline value outside them (CIS asks for a 15-character password, Intune allows 4-14) is
# checked with mSCP's own check in the discovery script instead; Intune would reject it with a 400.
BUILTIN_RANGES: dict[Platform, dict[str, tuple[int, int]]] = {
    Platform.MACOS: {
        "passwordMinimumLength": (4, 14),
        "passwordPreviousPasswordBlockCount": (1, 24),
        "passwordExpirationDays": (1, 65535),
    },
    Platform.IOS: {},
}


def _out_of_range(props: dict[str, Any], platform: Platform) -> tuple[str, Any, tuple[int, int]] | None:
    for prop, value in props.items():
        lo_hi = BUILTIN_RANGES[platform].get(prop)
        if lo_hi and isinstance(value, (int, float)) and not isinstance(value, bool):
            if not lo_hi[0] <= value <= lo_hi[1]:
                return prop, value, lo_hi
    return None


def _builtin_value(rule_id: str, platform: Platform, odv: Any) -> dict[str, Any] | None:
    check = coverage.COMPLIANCE_CHECKS[platform].get(rule_id)
    if not check:
        return None
    prop, kind = check
    if kind == "true":
        value: Any = True
    elif kind.startswith("one_of:"):
        value = kind[len("one_of:"):].split(",")[-1]  # the most permissive allowed value
    else:
        if odv is None:
            return None
        value = int(odv) if float(odv).is_integer() else odv
    props = {prop: value}
    pw = coverage.PASSWORD_REQUIRED[platform]
    if prop.startswith(("password", "passcode")) and prop != pw:
        props[pw] = True
    return props


def builtin_off(platform: Platform) -> dict[str, Any]:
    """Every built-in setting this tool can use, at Intune's 'not configured' value."""
    off: dict[str, Any] = {coverage.PASSWORD_REQUIRED[platform]: False}
    for prop, kind in coverage.COMPLIANCE_CHECKS[platform].values():
        if kind == "true":
            off[prop] = False
        elif prop == "gatekeeperAllowedAppSource":
            off[prop] = "notConfigured"
        elif prop.endswith("RequiredType"):
            off[prop] = "deviceDefault"
        else:
            off[prop] = None
    return off


def select(
    base: Baseline,
    platform: Platform,
    scan: coverage.TenantScan | None,
    *,
    sections: list[str] | None = None,
    include_per_user: bool = False,
    merge: list[str] | None = None,
    include_builtin: bool = True,
) -> dict[str, Any]:
    merge = DEFAULT_MERGE if merge is None else merge
    parent = getattr(base, "parent_values", "") or ""
    plans: list[SectionPlan] = []
    skipped: list[dict] = []
    attention: list[dict] = []
    compliance = scan.compliance if scan else []
    for prof in base.profile:
        if sections and prof.section not in sections:
            continue
        plan = SectionPlan(prof.section)
        for rule in prof.rules:
            how = classify.delivery(rule)
            odv = classify.odv_value(rule, parent)
            ver = coverage.rule_verification(rule.rule_id, platform, odv, compliance) if scan else None
            if ver and ver["status"].startswith("verified"):
                skipped.append({"rule": rule.rule_id, "why": "already checked",
                                "by": sorted({f["name"] for f in ver["found_in"] if f["meets_baseline"]})})
                continue
            if ver and ver["status"] == "compliance_different_value":
                attention.append({"rule": rule.rule_id, "why": "a compliance policy checks it with a weaker value",
                                  "found": [f"{f['name']}: {f['value']}" for f in ver["found_in"]]})
            builtin = _builtin_value(rule.rule_id, platform, odv)
            if builtin and not include_builtin:
                # macOS default: mSCP's own check in the script instead. Built-in password settings
                # make the Mac ask for a new password, and some Macs ignore the script part of a
                # policy that also has built-in settings (seen on a user-enrolled macOS 26 VM).
                if platform.supports_custom_compliance and (rule.check or "").strip():
                    how = "script"
                    builtin = None  # no mSCP check: the built-in setting stays, it's the only way to check it
            beyond = _out_of_range(builtin, platform) if builtin else None
            if beyond:
                prop, value, (lo, hi) = beyond
                if platform.supports_custom_compliance and (rule.check or "").strip():
                    attention.append({"rule": rule.rule_id,
                                      "why": f"Intune's built-in {prop} allows {lo}-{hi}, the baseline asks "
                                             f"for {value}: checked with mSCP's check in the script instead"})
                    how = "script"  # fall through to the script path below
                else:
                    skipped.append({"rule": rule.rule_id,
                                    "why": f"Intune's built-in {prop} allows {lo}-{hi}, the baseline asks for {value}"})
                    continue
            elif builtin:
                plan.builtin.update(builtin)
                plan.builtin_rules.append(rule.rule_id)
                continue
            if how != "script" and not ddm_not_in_catalog(rule):
                continue  # profile/DDM rules are enforced by configuration policies
            if not platform.supports_custom_compliance:
                skipped.append({"rule": rule.rule_id, "why": "iOS/iPadOS has no custom compliance"})
                continue
            if not (rule.check or "").strip() or set(rule.tags or []) & NOT_SCRIPTABLE_TAGS:
                skipped.append({"rule": rule.rule_id, "why": "no automated check in mSCP"})
                continue
            if _per_user(rule) and not include_per_user:
                skipped.append({"rule": rule.rule_id, "why": "reads the logged-in user's settings (include_per_user to add)"})
                continue
            (plan.merged if prof.section in merge else plan.scripted).append(rule)
        if not plan.empty():
            plans.append(plan)
    return {"sections": plans, "skipped": skipped, "attention": attention}


# ------------------------------------------------------------------- script


def _zsh_string(text: str) -> str:
    return "'" + str(text).replace("'", "'\\''") + "'"


def _eval_body(text: str) -> str:
    """mSCP's check/fix text as the body of a zsh function, run with eval.

    Not pasted in indented: heredoc terminators (EOS) must start a line, and a heredoc
    missing its terminator would swallow the rest of the script. As a quoted string
    each one runs exactly as mSCP wrote it, standalone."""
    return "  eval " + _zsh_string(str(text).rstrip())


def is_base64_result(rule: Macsecurityrule) -> bool:
    """mSCP rules whose check output is base64 (result: {base64: ...}), e.g. the login window text."""
    try:
        result = rule.platforms["macOS"]["enforcement_info"]["check"]["result"]
    except (AttributeError, KeyError, TypeError):
        return False
    return isinstance(result, dict) and "base64" in result


def expected_output(rule: Macsecurityrule) -> str:
    """What the check prints when the rule is met. mSCP's own loader keeps result_value as plain
    text for base64 results (its str branch matches first), while the check pipes through base64:
    encode it here so the comparison works. With the trailing newline: the check pipes osascript's
    output (which ends in one) through base64, as a real Mac reports (".../IQo=" for "...!\\n")."""
    value = str(rule.result_value)
    if is_base64_result(rule):
        import base64 as _b64
        return _b64.b64encode((value + "\n").encode("utf-8")).decode()
    return value


def _arch(rule: Macsecurityrule) -> str:
    tags = set(rule.tags or [])
    return "arm64" if "arm64" in tags else "i386" if "i386" in tags else ""


def discovery_script(plan: SectionPlan, *, name: str, mscp_version: str, baseline: str) -> str:
    """A bash script whose body runs mSCP's checks in zsh and prints one JSON line."""
    lines = [
        "#!/bin/bash",
        f"# {name}",
        "# Intune custom compliance discovery script, generated by apple-intune-baseline",
        f"# from mSCP {mscp_version}, baseline {baseline}, section {plan.section}.",
        "# Read-only: runs mSCP's own checks and reports pass/fail; it changes nothing.",
        "# Intune requires a bash shebang; mSCP checks are written for zsh, so they run in zsh.",
        "# The checks are passed to zsh as an argument (stdin stays closed, so no check can read it).",
        "# read -d '' instead of $(cat <<...): bash 3.2 on macOS misparses quotes inside that form.",
        "IFS= read -r -d '' MSCP_CHECKS <<'MSCP_CHECKS_END'",
        "export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec",
        "CURRENT_USER=$(/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow lastUserName 2>/dev/null)",
        "CURR_USER_UID=$(/usr/bin/id -u \"$CURRENT_USER\" 2>/dev/null)",
        "arch=$(/usr/bin/arch)",
        "typeset -A out",
        "typeset -a failed",
        "",
        "# run_check <rule_id> <expected> <arch> <function>: true when the output matches",
        "run_check() {",
        "  local rule_id=$1 expected=$2 rule_arch=$3 fn=$4",
        "  if [[ -n \"$rule_arch\" && \"$arch\" != \"$rule_arch\" ]]; then return 0; fi",
        "  local result",
        "  result=$($fn 2>/dev/null)",
        "  [[ \"$result\" == \"$expected\" ]]",
        "}",
        "",
    ]
    def block(rule: Macsecurityrule, i: int) -> tuple[list[str], str]:
        fn = f"check_{i}"
        return [
            f"# ----- {rule.rule_id}: {' '.join(str(rule.title).split())}",
            f"{fn}() {{",
            _eval_body(rule.check),
            "}",
        ], fn

    i = 0
    for rule in plan.scripted:
        i += 1
        body, fn = block(rule, i)
        lines += body
        lines += [
            f"if run_check {rule.rule_id} {_zsh_string(expected_output(rule))} {_zsh_string(_arch(rule))} {fn}; "
            f"then out[{rule.rule_id}]=true; else out[{rule.rule_id}]=false; fi",
            "",
        ]
    for rule in plan.merged:
        i += 1
        body, fn = block(rule, i)
        lines += body
        lines += [
            f"run_check {rule.rule_id} {_zsh_string(expected_output(rule))} {_zsh_string(_arch(rule))} {fn} "
            f"|| failed+=({rule.rule_id})",
            "",
        ]
    lines += ["# one line of JSON on stdout, nothing else", "json=\"{\""]
    for rule in plan.scripted:
        lines.append(f"json+=\"\\\"{rule.rule_id}\\\":${{out[{rule.rule_id}]}},\"")
    if plan.merged:
        lines.append(f"json+=\"\\\"{setting_for_section(plan.section)}\\\":\\\"${{(j:,:)failed}}\\\",\"")
    lines += [
        "json=\"${json%,}}\"",
        "print -r -- \"$json\"",
        "exit 0",
        "MSCP_CHECKS_END",
        "exec /bin/zsh --no-rcs -c \"$MSCP_CHECKS\" </dev/null",
        "",
    ]
    return "\n".join(lines)


# -------------------------------------------------------------------- rules


def rules_json(plan: SectionPlan, more_info: str) -> dict[str, Any]:
    rules = []
    for rule in plan.scripted:
        title = " ".join(str(rule.title).split())
        rules.append({
            "SettingName": rule.rule_id,
            "Operator": "IsEquals",
            "DataType": "Boolean",
            "Operand": True,
            "MoreInfoUrl": more_info,
            "RemediationStrings": [{
                "Language": "en_US",
                "Title": title,
                "Description": f"This Mac doesn't meet the security requirement \"{title}\". "
                               "Contact your IT department.",
            }],
        })
    if plan.merged:
        rules.append({
            "SettingName": setting_for_section(plan.section),
            "Operator": "IsEquals",
            "DataType": "String",
            "Operand": "",
            "MoreInfoUrl": more_info,
            "RemediationStrings": [{
                "Language": "en_US",
                "Title": f"{plan.section} settings don't meet the security baseline",
                "Description": "Failing checks: {ActualValue}. Contact your IT department.",
            }],
        })
    return {"Rules": rules}


def _description(source: str, baseline: str, plan: SectionPlan) -> str:
    lines = [f"Generated by apple-intune-baseline from mSCP {source}", f"Baseline: {baseline}",
             f"Section: {plan.section}"]
    if plan.builtin_rules:
        lines += ["Built-in checks:"] + plan.builtin_rules
    if plan.scripted:
        lines += ["Script checks:"] + [r.rule_id for r in plan.scripted]
    if plan.merged:
        lines += [f"Merged into {setting_for_section(plan.section)}:"] + [r.rule_id for r in plan.merged]
    text = "\n".join(lines)
    return text if len(text) <= 1000 else text[:990].rsplit("\n", 1)[0] + "\n..."


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
    more_info: str,
    grace_hours: int,
) -> list[dict[str, Any]]:
    from .generate import policy_name, slug

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    policies = []
    for plan in result["sections"]:
        name = policy_name(prefix, platform, baseline_display, os_version, plan.section, "Compliance")
        body: dict[str, Any] = {
            "@odata.type": platform.compliance_policy_type,
            "displayName": name,
            "description": _description(mscp_version, baseline_name, plan),
            "roleScopeTagIds": ["0"],
            **builtin_off(platform),  # explicit, so replacing an older policy also clears what it had set
            **plan.builtin,
            "scheduledActionsForRule": [{
                "ruleName": "PasswordRequired",
                "scheduledActionConfigurations": [{
                    "actionType": "block", "gracePeriodHours": grace_hours,
                    "notificationTemplateId": "", "notificationMessageCCList": [],
                }],
            }],
        }
        entry: dict[str, Any] = {
            "name": name, "section": plan.section, "file": f"{slug(name)}.json",
            "builtin": plan.builtin_rules, "builtin_settings": plan.builtin,
            "script_checks": [r.rule_id for r in plan.scripted],
            "merged_checks": [r.rule_id for r in plan.merged],
        }
        if plan.scripted or plan.merged:
            script_name = f"{name} - Discovery Script"
            script = discovery_script(plan, name=script_name, mscp_version=mscp_version, baseline=baseline_name)
            rules = rules_json(plan, more_info)
            (out_dir / f"{slug(name)}.sh").write_text(script, encoding="utf-8")
            # Graph body for /deviceManagement/deviceComplianceScripts, same shape as a macOS
            # script created in the Intune portal (platform macOS, runs as root).
            (out_dir / f"{slug(name)}.script.json").write_text(json.dumps({
                "displayName": script_name,
                "description": f"Discovery script for '{name}'. mSCP {mscp_version}, baseline {baseline_name}.",
                "publisher": "apple-intune-baseline",
                "detectionScriptContent": base64.b64encode(script.encode()).decode(),
                "runAsAccount": "system",
                "enforceSignatureCheck": False,
                "runAs32Bit": False,
                "platform": "macOS",
                "roleScopeTagIds": ["0"],
            }, indent=2), encoding="utf-8")
            # Indented, so the rules stay readable where Intune shows them in the portal.
            rules_text = json.dumps(rules, indent=2, ensure_ascii=False) + "\n"
            (out_dir / f"{slug(name)}.rules.json").write_text(rules_text, encoding="utf-8")
            # filled in at push time with the ID of the uploaded discovery script
            body["deviceCompliancePolicyScript"] = {
                "deviceComplianceScriptId": "{{DISCOVERY_SCRIPT_ID}}",
                "rulesContent": base64.b64encode(rules_text.encode("utf-8")).decode(),
            }
            entry |= {"script": f"{slug(name)}.sh", "rules_json": f"{slug(name)}.rules.json",
                      "script_body": f"{slug(name)}.script.json",
                      "script_name": script_name, "settings": len(rules["Rules"])}
        (out_dir / entry["file"]).write_text(json.dumps(body, indent=2), encoding="utf-8")
        policies.append(entry)
    return policies
