"""Remediation: Intune shell scripts built from mSCP's own fixes.

For rules no Settings Catalog policy or custom profile can enforce (mSCP's
``Script`` rules: launchd services, sudoers, file permissions, pmset...), one
macOS shell script per mSCP section. For each rule the script:

1. runs mSCP's ``check`` (exactly as the compliance discovery script does),
2. only if it fails, runs mSCP's ``fix`` unchanged,
3. runs the check again and logs ok / fixed / still failing.

So it is safe to run repeatedly (Intune can run it daily to undo drift), and a
Mac that already passes is never touched. Output goes to
``/Library/Logs/apple-intune-baseline/<script>.log``; the script exits 1 when a
rule is still failing, so Intune shows the run as failed.

Left out, with the reason:

* rules that need macOS Recovery or SIP turned off (``csrutil``, ``nvram``),
  which no script on a running Mac can change
* disruptive fixes (installing every update with a possible restart) unless
  asked for; DDM software update enforcement does that job better
* fixes that act on the last logged-in user, unless asked for
* rules mSCP has no automated fix for
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
from . import classify
from .compliance import NOT_SCRIPTABLE_TAGS, _arch, _eval_body, _per_user, _zsh_string, expected_output
from .platforms import Platform

if TYPE_CHECKING:
    from mscp.classes.baseline import Baseline
    from mscp.classes.macsecurityrule import Macsecurityrule

LOG_DIR = "/Library/Logs/apple-intune-baseline"
FREQUENCIES = {"once": None, "daily": "P1D", "weekly": "P7D"}

NEEDS_RECOVERY = re.compile(r"\bcsrutil\b|\bnvram\b")
DISRUPTIVE = re.compile(r"softwareupdate\s+(-[a-zA-Z]*i|--install)|\bshutdown\b|\breboot\b")


@dataclass
class SectionFix:
    section: str
    rules: list[Any] = field(default_factory=list)
    also_scripted: dict[str, str] = field(default_factory=dict)  # non-script rule -> why the fix runs too


def _uses_user(rule: Macsecurityrule) -> bool:
    fix = rule.fix or ""
    return _per_user(rule) or "CURRENT_USER" in fix or "CURR_USER_UID" in fix


# Rules a profile delivers but doesn't fully enforce, so mSCP's fix script runs too (it checks
# first, so Macs that already pass are untouched).
PROFILE_NOT_ENOUGH = {
    "os_unlock_active_user_session_disable":
        "with Platform SSO, system.login.screensaver points at PSSO's own rule (owner or admin), which "
        "the profile's screenUnlockMode doesn't change; mSCP's fix writes an owner-only copy of it",
}


def select(
    base: Baseline,
    platform: Platform,
    *,
    sections: list[str] | None = None,
    exclude: list[str] | None = None,
    include: list[str] | None = None,
    include_per_user: bool = False,
    include_disruptive: bool = False,
) -> dict[str, Any]:
    if not platform.supports_custom_compliance:  # macOS only, like custom compliance
        return {"sections": [], "skipped": [], "not_found": []}
    exclude_set = set(exclude or [])
    include_set = set(include or [])
    plans: list[SectionFix] = []
    skipped: list[dict] = []
    in_baseline = set()
    for prof in base.profile:
        if sections and prof.section not in sections:
            continue
        plan = SectionFix(prof.section)
        for rule in prof.rules:
            in_baseline.add(rule.rule_id)
            also = PROFILE_NOT_ENOUGH.get(rule.rule_id) or (
                "Intune can't send this declaration (not in the Settings Catalog); mSCP's fix enforces it"
                if ddm_not_in_catalog(rule) else None)
            if classify.delivery(rule) != "script" and not also and rule.rule_id not in include_set:
                continue  # Settings Catalog / custom profile / DDM rules are enforced by policies
            fix = (rule.fix or "").strip()
            why = None
            if rule.rule_id in exclude_set:
                why = "left out on request"
            elif not fix or set(rule.tags or []) & NOT_SCRIPTABLE_TAGS:
                why = "no automated fix in mSCP"
            elif not (rule.check or "").strip():
                why = "no check in mSCP, so the fix can't be applied only when needed"
            elif NEEDS_RECOVERY.search(fix):
                why = "needs macOS Recovery or SIP turned off (csrutil/nvram); a script can't change it"
            elif DISRUPTIVE.search(fix) and not include_disruptive:
                why = ("installs updates and may restart the Mac; use DDM software update enforcement "
                       "(include_disruptive to add)")
            elif _uses_user(rule) and not include_per_user:
                why = "changes the last logged-in user's settings (include_per_user to add)"
            if why:
                skipped.append({"rule": rule.rule_id, "why": why})
                continue
            if classify.delivery(rule) != "script":
                plan.also_scripted[rule.rule_id] = also or "added on request; a policy delivers it too"
            plan.rules.append(rule)
        if plan.rules:
            plans.append(plan)
    return {"sections": plans, "skipped": skipped,
            "not_found": sorted((exclude_set | include_set) - in_baseline)}


# ------------------------------------------------------------------- script


def _title(rule: Macsecurityrule) -> str:
    return " ".join(str(rule.title).split())


def remediation_script(plan: SectionFix, *, name: str, mscp_version: str, baseline: str, log_name: str) -> str:
    """A bash script whose body checks, fixes and re-checks each rule in zsh."""
    lines = [
        "#!/bin/bash",
        f"# {name}",
        "# Intune shell script generated by apple-intune-baseline",
        f"# from mSCP {mscp_version}, baseline {baseline}, section {plan.section}.",
        "# For each rule: run mSCP's check; only if it fails, run mSCP's fix; then check again.",
        "# A Mac that already passes is not changed. Safe to run repeatedly.",
        f"# Log: {LOG_DIR}/{log_name}",
        "#",
        "# Rules:",
        *(f"#   {r.rule_id} - {_title(r)}" for r in plan.rules),
        "#",
        "# Intune requires a bash shebang; mSCP's checks and fixes are written for zsh, so they run",
        "# in zsh. read -d '' instead of $(cat <<...): bash 3.2 on macOS misparses quotes inside that.",
        "IFS= read -r -d '' MSCP_FIXES <<'MSCP_FIXES_END'",
        "export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec",
        "CURRENT_USER=$(/usr/bin/defaults read /Library/Preferences/com.apple.loginwindow lastUserName 2>/dev/null)",
        "CURR_USER_UID=$(/usr/bin/id -u \"$CURRENT_USER\" 2>/dev/null)",
        "arch=$(/usr/bin/arch)",
        f"LOG={LOG_DIR}/{log_name}",
        f"/bin/mkdir -p {LOG_DIR}",
        "mscp_log() { print -r -- \"$(/bin/date '+%Y-%m-%d %H:%M:%S') $*\" >> \"$LOG\" }",
        "typeset -a ok fixed failing",
        "",
        "# remediate <rule_id> <expected> <arch> <check function> <fix function>",
        "remediate() {",
        "  local rule_id=$1 expected=$2 rule_arch=$3 check=$4 fix=$5",
        "  print -r -- \"$rule_id\" > \"$LOG.running\"  # the wrapper reports it if the run dies here",
        "  if [[ -n \"$rule_arch\" && \"$arch\" != \"$rule_arch\" ]]; then return 0; fi",
        "  if [[ \"$($check 2>/dev/null)\" == \"$expected\" ]]; then ok+=($rule_id); return 0; fi",
        "  mscp_log \"$rule_id: check failed, running mSCP fix\"",
        "  ( $fix ) >> \"$LOG\" 2>&1 </dev/null",
        "  if [[ \"$($check 2>/dev/null)\" == \"$expected\" ]]; then",
        "    fixed+=($rule_id); mscp_log \"$rule_id: fixed\"",
        "  else",
        "    failing+=($rule_id); mscp_log \"$rule_id: still failing (some fixes need a restart)\"",
        "  fi",
        "}",
        "",
        "/bin/rm -f \"$LOG.running\"",
        f"mscp_log \"----- start: {name}\"",
        "",
    ]
    for i, rule in enumerate(plan.rules, 1):
        lines += [
            f"# ===== BEGIN {rule.rule_id}: {_title(rule)}",
            f"check_{i}() {{",
            _eval_body(rule.check),
            "}",
            f"fix_{i}() {{",
            _eval_body(rule.fix),
            "}",
            f"remediate {rule.rule_id} {_zsh_string(expected_output(rule))} {_zsh_string(_arch(rule))} "
            f"check_{i} fix_{i}",
            f"# ===== END {rule.rule_id}",
            "",
        ]
    lines += [
        "summary=\"ok: ${#ok}, fixed: ${#fixed}, still failing: ${#failing}\"",
        "(( ${#fixed} )) && summary+=\" | fixed: ${(j:,:)fixed}\"",
        "(( ${#failing} )) && summary+=\" | failing: ${(j:,:)failing}\"",
        "mscp_log \"----- done: $summary\"",
        "/bin/rm -f \"$LOG.running\"",
        "print -r -- \"$summary\"",
        "# Intune drops a failed run's stdout and shows its stderr (errorDescription): say it there too",
        "(( ${#failing} )) && { print -r -- \"$summary\" >&2; exit 1 }",
        "exit 0",
        "MSCP_FIXES_END",
        "/bin/zsh --no-rcs -c \"$MSCP_FIXES\" </dev/null",
        "rc=$?",
        "# The run died before its summary (a fix or check crashed or was stopped): say where, so",
        "# Intune shows more than an empty failure.",
        f"if [ -f \"{LOG_DIR}/{log_name}.running\" ]; then",
        f"  msg=\"error: stopped before finishing, during $(/bin/cat \"{LOG_DIR}/{log_name}.running\") "
        f"(exit $rc); see {LOG_DIR}/{log_name}\"",
        "  echo \"$msg\"; echo \"$msg\" >&2",
        f"  /bin/rm -f \"{LOG_DIR}/{log_name}.running\"",
        "  [ \"$rc\" -eq 0 ] && rc=2",
        "fi",
        "exit $rc",
        "",
    ]
    return "\n".join(lines)


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
    frequency: str,
) -> list[dict[str, Any]]:
    from .generate import _description, policy_name, slug

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    scripts = []
    for plan in result["sections"]:
        name = policy_name(prefix, platform, baseline_display, os_version, plan.section, "Remediation")
        file_sh = f"{slug(name)}.sh"
        script = remediation_script(plan, name=name, mscp_version=mscp_version, baseline=baseline_name,
                                    log_name=f"{slug(name)}.log")
        (out_dir / file_sh).write_text(script, encoding="utf-8")
        titles = {r.rule_id: _title(r) for r in plan.rules}
        body: dict[str, Any] = {
            "@odata.type": "#microsoft.graph.deviceShellScript",
            "displayName": name,
            "description": _description(mscp_version, baseline_name, plan.section,
                                        [r.rule_id for r in plan.rules], titles),
            "scriptContent": base64.b64encode(script.encode("utf-8")).decode(),
            "runAsAccount": "system",
            "fileName": file_sh,
            "blockExecutionNotifications": True,
            "retryCount": 0,
            "roleScopeTagIds": ["0"],
        }
        if FREQUENCIES[frequency]:
            body["executionFrequency"] = FREQUENCIES[frequency]
        (out_dir / f"{slug(name)}.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
        scripts.append({"name": name, "section": plan.section, "file": f"{slug(name)}.json", "script": file_sh,
                        "rules": [r.rule_id for r in plan.rules], "frequency": frequency,
                        **({"also_scripted": plan.also_scripted} if plan.also_scripted else {})})
    return scripts
