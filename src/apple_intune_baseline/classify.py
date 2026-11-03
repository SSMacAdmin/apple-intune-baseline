"""Turns an mSCP rule into the facts the overview needs.

* **Delivery**: how the rule reaches a device, from mSCP's ``mechanism``.
* **Verification**: what (if anything) checks it in Intune.
* **Impact tags**: what users will notice. mSCP has no such field, so this is
  a small curated map that ships with the MCP. Edit ``IMPACT_PATTERNS`` to
  tune it.

Tenant coverage ("already configured in profile X") is a later phase and is
reported as ``not_checked`` until then.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .platforms import Platform

if TYPE_CHECKING:
    from mscp.classes.macsecurityrule import Macsecurityrule

# Sections where nothing is deployed: Apple enforces it, it can't be fixed, or it doesn't apply.
NOT_ACTIONABLE_SECTIONS = {"Inherent", "Permanent Findings", "Not Applicable", "Supplemental"}

DELIVERY_LABELS = {
    "ddm": "Settings Catalog (DDM)",
    "profile": "Settings Catalog / custom profile",
    "script": "Script-only (no payload)",
    "manual": "Manual / policy document",
    "not_actionable": "Inherent, permanent, n/a or supplemental",
}

# Rules an Intune built-in compliance setting already verifies. Use the toggle, don't script it.
BUILTIN_COMPLIANCE: dict[Platform, dict[str, str]] = {
    Platform.MACOS: {
        "system_settings_filevault_enforce": "Encryption of data storage on device (FileVault)",
        "system_settings_firewall_enable": "Firewall",
        "system_settings_firewall_stealth_mode_enable": "Stealth mode",
        "os_sip_enable": "Require system integrity protection",
        "os_gatekeeper_enable": "Allow apps downloaded from these locations (Gatekeeper)",
        "pwpolicy_minimum_length_enforce": "Minimum password length",
        "pwpolicy_simple_sequence_disable": "Simple passwords",
        "pwpolicy_alpha_numeric_enforce": "Password type",
        "pwpolicy_history_enforce": "Number of previous passwords to prevent reuse",
        "pwpolicy_max_lifetime_enforce": "Password expiration (days)",
    },
    Platform.IOS: {
        "pwpolicy_force_pin_enable": "Require a password to unlock mobile devices",
        "pwpolicy_minimum_length_enforce": "Minimum password length",
        "pwpolicy_simple_sequence_disable": "Simple passwords",
        "pwpolicy_alpha_numeric_enforce": "Required password type",
        "pwpolicy_history_enforce": "Number of previous passwords to prevent reuse",
        "pwpolicy_max_inactivity_enforce": "Maximum minutes of inactivity until screen locks",
        "pwpolicy_max_grace_period_enforce": "Maximum minutes after screen lock before password is required",
    },
}

# Curated, deliberately simple. Matched against the rule ID.
IMPACT_PATTERNS: dict[str, re.Pattern[str]] = {
    "breaks_workflows": re.compile(
        r"ssh|screen_sharing|screen_observation|remote_management|remote_apple_events|airdrop"
        r"|smbd|file_sharing|bluetooth_sharing|printer_sharing|internet_sharing|airplay"
        r"|handoff|universal_control|sidecar|icloud_(drive|desktop|sync)|usb|media_sharing"
        r"|content_caching|camera"
    ),
    "user_visible": re.compile(
        r"screensaver|screen_?lock|pwpolicy|password|passcode|loginwindow|login_window|guest"
        r"|siri|touch_?id|dictation|safari|notification|banner|lock_screen|show_full_name"
        r"|wallpaper|setup_assistant|skip_"
    ),
    "apple_intelligence": re.compile(
        r"intelligence|writing_tools|summary|summarization|genmoji|image_playground|chatgpt"
        r"|transcription|smart_reply|mail_summary|personalized_handwriting|siri_ai"
    ),
}


def delivery(rule: Macsecurityrule) -> str:
    if rule.section in NOT_ACTIONABLE_SECTIONS:
        return "not_actionable"
    mech = (rule.mechanism or "").lower()
    if "declarative" in mech:
        return "ddm"
    if "configuration profile" in mech:
        return "profile"
    if mech == "script":
        return "script"
    return "manual"


def verification(rule: Macsecurityrule, platform: Platform) -> dict[str, Any]:
    """What checks this rule in Intune, given the decisions in the design doc."""
    builtin = BUILTIN_COMPLIANCE[platform].get(rule.rule_id)
    if builtin:
        return {"status": "builtin_compliance", "intune_setting": builtin}
    how = delivery(rule)
    from .mapping import ddm_not_in_catalog
    if how == "ddm" and ddm_not_in_catalog(rule):
        how = "script"  # Intune can't send the declaration: mSCP's scripts check and fix it
    if how in ("ddm", "profile"):
        return {"status": "enforced_not_verified"}
    if how == "script":
        if platform.supports_custom_compliance:
            return {"status": "custom_compliance_candidate"}
        return {"status": "unverifiable"}
    return {"status": "none"}


def impact_tags(rule: Macsecurityrule) -> list[str]:
    return [tag for tag, pat in IMPACT_PATTERNS.items() if pat.search(rule.rule_id)]


def odv_value(rule: Macsecurityrule, parent_values: str) -> Any:
    """The organization-defined value this baseline applies, if the rule has one.

    Same precedence as mSCP: a workspace customization ("custom") wins, then the
    parent baseline's value, then "recommended"."""
    odv = rule.odv or {}
    if not odv:
        return None
    keys = ("custom",) if "odv" in (getattr(rule, "customized", None) or []) else ()
    for key in (*keys, parent_values, "recommended"):
        if key and key in odv:
            return odv[key]
    return None


def payloads(rule: Macsecurityrule) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if rule.mobileconfig_info:
        out["mobileconfig"] = [
            {"payload_type": p.payload_type, "settings": p.payload_content}
            for p in rule.mobileconfig_info
        ]
    if rule.ddm_info:
        out["ddm"] = rule.ddm_info
    return out


def references(rule: Macsecurityrule) -> dict[str, Any]:
    """Framework references, flattened to the ones admins and auditors ask about."""
    refs = rule.references.model_dump(exclude_none=True) if rule.references else {}
    nist, disa, cis = refs.get("nist", {}), refs.get("disa", {}), refs.get("cis", {})
    flat = {
        "800-53r5": nist.get("nist_800_53r5"),
        "800-171r3": nist.get("nist_800_171r3"),
        "cis_benchmark": cis.get("benchmark"),
        "cis_controls_v8": cis.get("controls_v8"),
        "disa_stig": disa.get("disa_stig"),
        "cmmc": disa.get("cmmc"),
        "cce": nist.get("cce"),
    }
    return {k: v for k, v in flat.items() if v}
