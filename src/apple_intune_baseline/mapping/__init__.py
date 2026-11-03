"""mSCP rule payloads -> Intune Settings Catalog setting definition IDs.

The naming rules were confirmed against Graph's configurationSettings on
2026-10-18 (see README.md in this folder):

* MDM settings: ``<payload type>_<key>``, lowercased.
* DDM settings: a short group prefix per declaration type, then the key path
  joined with ``_``, lowercased.

``settings_catalog_map.tsv`` records which of those IDs actually exist in the
catalog, so a rule whose IDs are missing is known to need a custom profile.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mscp.classes.macsecurityrule import Macsecurityrule

# Settings that live under a different ID in Intune than the payload suggests. None today:
# com.apple.screensaver idleTime is NOT com.apple.screensaver.user_idletime (that's the user
# channel; mSCP sets and checks the device-level domain), so it goes in a custom profile.
ALIASES: dict[str, str] = {}

# Managed Client preferences: one payload type for any preference domain, settings nested as
# PayloadContent -> {domain: {Forced: [{mcx_preference_settings: {...}}]}}. Internally each
# domain is its own payload type "com.apple.ManagedClient.preferences/<domain>", so keys from
# several rules merge per domain and compare per key.
MCX = "com.apple.ManagedClient.preferences"


def payload_leaves(rule: "Macsecurityrule") -> list[tuple[str, str, Any]]:
    """(payload type, key, value) for every key a rule's profile payloads set, MCX per domain."""
    out = []
    for payload in rule.mobileconfig_info or []:
        for content in payload.payload_content:
            for key, val in content.items():
                if payload.payload_type == MCX and isinstance(val, dict):
                    out += [(f"{MCX}/{key}", k, v) for k, v in val.items()]
                else:
                    out.append((payload.payload_type, key, val))
    return out

# DDM declaration type -> Settings Catalog group prefix.
DDM_PREFIX = {
    "com.apple.configuration.passcode.settings": "passcode",
    "com.apple.configuration.intelligence.settings": "intelligencesettings",
    "com.apple.configuration.softwareupdate.settings": "softwareupdate",
    "com.apple.configuration.app.settings": "app",
    "com.apple.configuration.keyboard.settings": "keyboardsettings",
    "com.apple.configuration.external-intelligence.settings": "externalintelligencesettings",
    "com.apple.configuration.siri.settings": "sirisettings",
    "com.apple.configuration.diskmanagement.settings": "diskmanagement",
}


@dataclass(frozen=True)
class Expected:
    """One setting a rule wants, and the value it wants."""

    setting_id: str  # Settings Catalog ID we derived (may not exist in the catalog)
    value: Any  # expected value; dict/list means "compare not supported"
    payload_type: str  # MDM payload type or DDM declaration type
    key: str  # payload key, or DDM key path joined with "."
    in_catalog: bool


@lru_cache(maxsize=1)
def known_ids() -> frozenset[str]:
    text = files(__package__).joinpath("settings_catalog_map.tsv").read_text(encoding="utf-8")
    ids: set[str] = set()
    rows = csv.reader((line for line in text.splitlines() if not line.startswith("#")), delimiter="\t")
    header = next(rows)
    col = header.index("setting_ids")
    for row in rows:
        if len(row) > col and row[col]:
            ids.update(row[col].split(","))
    return frozenset(ids)


def _ddm_leaves(base: str, path: str, value: Any):
    if isinstance(value, dict) and value:
        for k, v in value.items():
            yield from _ddm_leaves(f"{base}_{k.lower()}", f"{path}.{k}", v)
    else:
        yield base, path, value


def forms(rule: Macsecurityrule) -> list[str]:
    """The forms a rule can be configured in, its own mechanism first."""
    primary = "ddm" if rule.ddm_info and "declarative" in (rule.mechanism or "").lower() else "mdm"
    other = "mdm" if primary == "ddm" else "ddm"
    has_other = bool(rule.mobileconfig_info) if other == "mdm" else bool(rule.ddm_info)
    return [primary, other] if has_other else [primary]


def expected_settings(rule: Macsecurityrule, form: str | None = None) -> list[Expected]:
    """What a rule configures, in the form the Settings Catalog uses.

    ``form`` picks "ddm" or "mdm"; by default the rule's own mechanism decides.
    Many rules have both, and a tenant may use either.
    """
    known = known_ids()
    out: list[Expected] = []
    mech = (rule.mechanism or "").lower()
    if form is None:
        form = "ddm" if rule.ddm_info and "declarative" in mech else "mdm"
    if form == "ddm":
        if not rule.ddm_info:
            return []
        decl = rule.ddm_info.get("declarationtype", "")
        key = rule.ddm_info.get("ddm_key")
        prefix = DDM_PREFIX.get(decl)
        if prefix and key:
            for sid, path, val in _ddm_leaves(f"{prefix}_{key.lower()}", key, rule.ddm_info.get("ddm_value")):
                out.append(Expected(sid, val, decl, path, sid in known))
        else:
            out.append(Expected("", rule.ddm_info.get("ddm_value"), decl, key or "", False))
        return out
    for ptype, key, val in payload_leaves(rule):
        sid = f"{ptype}_{key}".lower()
        sid = ALIASES.get(sid, sid)
        out.append(Expected(sid, val, ptype, key, sid in known))
    return out


def ddm_not_in_catalog(rule: "Macsecurityrule") -> bool:
    """Declarative-only rules whose declaration Intune's Settings Catalog doesn't have (e.g. the
    services configuration-files declaration mSCP uses for sshd and PAM). Intune can't send them, so
    mSCP's check and fix scripts are the way to verify and enforce them."""
    if not rule.ddm_info or rule.mobileconfig_info:
        return False
    exps = expected_settings(rule, "ddm")
    return not exps or not all(e.in_catalog and e.setting_id for e in exps)
