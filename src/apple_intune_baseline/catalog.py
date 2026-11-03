"""Settings Catalog setting definitions, read from Graph and cached in the workspace.

The generator needs each setting's real shape: choice or simple, integer or
string, which group it sits in, which option ID means which value, and which
sibling settings Intune requires. That lives in
``/deviceManagement/configurationSettings/{id}``; definitions change rarely,
so they are cached for two weeks in ``settings_catalog_definitions.json``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .graph import GraphClient, GraphError

TTL = timedelta(days=14)
KEEP = (
    "@odata.type", "id", "rootDefinitionId", "displayName", "options", "dependentOn",
    "dependedOnBy", "defaultOptionId", "defaultValue", "valueDefinition", "childIds",
)


def _slim(d: dict) -> dict:
    out = {k: d[k] for k in KEEP if k in d}
    if "options" in out:
        out["options"] = [
            {"itemId": o.get("itemId"), "value": (o.get("optionValue") or {}).get("value"),
             "dependentOn": o.get("dependentOn") or [], "dependedOnBy": o.get("dependedOnBy") or []}
            for o in out["options"] or []
        ]
    return out


class SettingDefinitions:
    def __init__(self, graph: GraphClient, cache_file: Path) -> None:
        self.graph = graph
        self.cache_file = cache_file
        try:
            self._cache = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._cache = {}
        self._dirty = False

    def get(self, setting_id: str) -> dict | None:
        """The definition, or None if the Settings Catalog has no such setting."""
        sid = setting_id.lower()
        hit = self._cache.get(sid)
        now = datetime.now(timezone.utc)
        if hit and now - datetime.fromisoformat(hit["fetched"]) < TTL:
            return hit["definition"]
        try:
            definition = _slim(self.graph.get(f"/deviceManagement/configurationSettings/{sid}"))
        except GraphError as e:
            if e.status not in (400, 404):
                raise
            definition = None
        self._cache[sid] = {"fetched": now.isoformat(), "definition": definition}
        self._dirty = True
        return definition

    def save(self) -> None:
        if self._dirty:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self._cache, indent=1, sort_keys=True), encoding="utf-8")
            self._dirty = False


def kind(d: dict) -> str:
    t = d.get("@odata.type", "").lower()
    for k in ("choicesettingcollection", "choicesetting", "simplesettingcollection", "simplesetting",
              "settinggroupcollection", "settinggroup"):
        if k + "definition" in t:
            return k
    return "unknown"


def parent_of(d: dict) -> tuple[str | None, str | None]:
    """(parent setting ID, option ID of the parent choice this hangs under, if any)."""
    if d.get("id") == d.get("rootDefinitionId"):
        return None, None
    deps = d.get("dependentOn") or []
    if not deps:
        for o in d.get("options") or []:
            if o.get("dependentOn"):
                deps = o["dependentOn"]
                break
    if not deps:
        return None, None
    pid = deps[0].get("parentSettingId")
    via = deps[0].get("dependentOn")
    return pid, (via if via and via != pid else None)


def required_children(d: dict) -> list[str]:
    return [x["dependedOnBy"] for x in d.get("dependedOnBy") or [] if x.get("required") and x.get("dependedOnBy")]


def _norm(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip().lower()


def choice_item(d: dict, value: Any) -> str | None:
    """The option ID for a value, e.g. False -> 'com.apple.applicationaccess_allowairdrop_false'."""
    sid = d["id"].lower()
    if isinstance(value, str) and value.lower().startswith(sid + "_"):
        if any((o.get("itemId") or "").lower() == value.lower() for o in d.get("options") or []):
            return value
        value = value[len(sid) + 1 :]
    want = _norm(value)
    # a boolean may be offered as 1/0 or, in Apple payloads such as FileVault2 Enable, On/Off or Yes/No
    alts = {"true": ("1", "on", "yes"), "false": ("0", "off", "no")}.get(want, ())
    for o in d.get("options") or []:
        if _norm(o.get("value")) == want:
            return o["itemId"]
    for alt in alts:
        for o in d.get("options") or []:
            if _norm(o.get("value")) == alt:
                return o["itemId"]
    return None


def simple_value(d: dict, value: Any) -> dict | None:
    vdef = d.get("valueDefinition") or {}
    vd = (vdef.get("@odata.type") or "").lower()
    if "integer" in vd:
        try:
            num = int(value)
        except (TypeError, ValueError):
            return None
        lo, hi = vdef.get("minimumValue"), vdef.get("maximumValue")
        if (lo is not None and num < lo) or (hi is not None and num > hi):
            return None
        return {"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue", "value": num}
    text = _norm(value) if isinstance(value, bool) else str(value)
    return {"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue", "value": text}
