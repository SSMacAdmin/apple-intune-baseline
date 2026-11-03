"""Push generated policies to Intune, unassigned, after the person approves.

Works from the files ``generate_policies`` wrote (``tenants/<tenant>/generated/<baseline>/policies/``), so
what is pushed is exactly what was reviewed. Two calls: without ``confirm`` it
only plans (create, replace, skip); with ``confirm`` it creates. Policies are
never assigned and never deleted here.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import UserInputError
from .graph import GraphClient, GraphError
from .platforms import Platform

STALE_AFTER_HOURS = 24


def load_plan(out_dir: Path) -> dict[str, Any]:
    try:
        return json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise UserInputError(
            "Nothing generated for this baseline yet"
            + (" (unsupervised variant). Run generate_policies with unsupervised=true"
               if out_dir.name.endswith("unsupervised") else ". Run generate_policies")
            + " first and review the result."
        ) from None


def existing_policies(graph: GraphClient, platform: Platform) -> dict[str, dict[str, Any]]:
    """Name -> {id, type} for this platform's Settings Catalog policies and custom profiles."""
    found: dict[str, dict[str, Any]] = {}
    for item in graph.get_all(
        "/deviceManagement/configurationPolicies",
        {"$select": "id,name", "$filter": f"platforms has '{platform.mscp_os}'"},
    ):
        found.setdefault(item.get("name", ""), {"id": item["id"], "type": "settings_catalog"})
    for item in graph.get_all("/deviceManagement/deviceConfigurations", {"$select": "id,displayName"}):
        if item.get("@odata.type") == platform.custom_profile_type:
            found.setdefault(item.get("displayName", ""), {"id": item["id"], "type": "custom_profile"})
    return found


def no_longer_generated(existing: dict[str, dict], own_prefix: str | None, generated: set[str]) -> list[str]:
    """Policies an earlier run of this baseline made that the current generated set doesn't have
    (e.g. a section moved from Settings Catalog to a custom profile). Never deleted here."""
    if not own_prefix:
        return []
    return sorted(n for n in existing if n.startswith(own_prefix) and n not in generated)


def plan_actions(plan: dict[str, Any], existing: dict[str, dict], replace: list[str] | None) -> list[dict]:
    replace = set(replace or [])
    actions = []
    for p in plan["policies"]:
        hit = existing.get(p["name"])
        if hit and hit["type"] != p["type"]:
            action = "skip_name_taken"
        elif hit and p["name"] in replace:
            action = "replace"
        elif hit:
            action = "skip_exists"
        else:
            action = "create"
        actions.append({"name": p["name"], "type": p["type"], "file": p["file"], "action": action,
                        "rules": len(p["rules"]), "settings": len(p["settings"]),
                        **({"existing_id": hit["id"]} if hit else {})})
    return actions


_NOISE = {"id", "settingInstanceTemplateReference", "settingValueTemplateReference", "auditRuleInformation"}


def _canon(value: Any) -> Any:
    """Settings as content only: no nulls, IDs or template references; lists order-free."""
    if isinstance(value, dict):
        return {k: _canon(v) for k, v in sorted(value.items()) if v is not None and k not in _NOISE}
    if isinstance(value, list):
        return sorted((_canon(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True, default=str))
    return value


def _profile(payload_b64: str | None) -> Any:
    import base64
    import plistlib

    try:
        return plistlib.loads(base64.b64decode(payload_b64 or ""))
    except Exception:  # noqa: BLE001 - unreadable counts as different
        return None


def compare_with_intune(graph: GraphClient, actions: list[dict], out_dir: Path) -> list[str]:
    """Mark each existing policy 'same' or 'differs' from the generated file (in_intune), so a
    regenerated baseline shows what a replace would change. Returns the names that differ."""
    differ = []
    for a in actions:
        if not a.get("existing_id") or a["action"] == "skip_name_taken":
            continue
        try:
            body = json.loads((out_dir / a["file"]).read_text(encoding="utf-8"))
            if a["type"] == "custom_profile":
                remote = graph.get(f"/deviceManagement/deviceConfigurations/{a['existing_id']}")
                same = _profile(remote.get("payload")) == _profile(body.get("payload"))
            else:
                remote = graph.get_all(f"/deviceManagement/configurationPolicies/{a['existing_id']}/settings")
                same = _canon([r.get("settingInstance") for r in remote]) == \
                    _canon([s.get("settingInstance") for s in body.get("settings", [])])
        except (OSError, ValueError, GraphError):
            a["in_intune"] = "unknown"
            continue
        a["in_intune"] = "same" if same else "differs"
        if not same:
            differ.append(a["name"])
    return differ


def blockers(plan: dict[str, Any], tenant_name: str, permission_set: str) -> list[str]:
    out = []
    if permission_set != "full":
        out.append(
            f"The app registration for '{tenant_name}' is read-only. Re-run setup_app_registration with "
            "permission_set='full' (it updates the existing app), then call again."
        )
    if plan.get("tenant") and plan["tenant"] != tenant_name:
        out.append(
            f"These files were generated against '{plan['tenant']}', not '{tenant_name}'. What to skip "
            "and the name prefix depend on the tenant: generate again for this tenant first."
        )
    missing = [a for a in plan.get("needs_attention", []) if a.get("status") == "needs_value"]
    if missing:
        out.append(
            "Settings still need a value: "
            + ", ".join(f"{a['setting']} ({a['policy']})" for a in missing)
            + ". Generate again with required_values."
        )
    return out


def warnings(plan: dict[str, Any]) -> list[str]:
    out = []
    when = plan.get("generated_at")
    if when:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(when)
        if age.total_seconds() > STALE_AFTER_HOURS * 3600:
            out.append(
                f"Generated {int(age.total_seconds() // 3600)} hours ago; the tenant may have changed since. "
                "Consider generating again first."
            )
    names = {p["name"] for p in plan.get("policies", [])}
    for h in plan.get("heads_up", []):  # only for the policies being pushed
        if h.get("policy") in names:
            out.append(f"Heads up ({h['rule']} in '{h['policy']}'): {h['note']}")
    return out


def execute(graph: GraphClient, actions: list[dict], out_dir: Path) -> list[dict]:
    results = []
    for a in actions:
        if a["action"] not in ("create", "replace"):
            results.append({**a, "result": "skipped"})
            continue
        body = json.loads((out_dir / a["file"]).read_text(encoding="utf-8"))
        try:
            if a["type"] == "settings_catalog":
                if a["action"] == "create":
                    made = graph.send("POST", "/deviceManagement/configurationPolicies", body)
                    pid = made.get("id")
                else:
                    pid = a["existing_id"]
                    graph.send("PUT", f"/deviceManagement/configurationPolicies/{pid}", body)
            else:
                if a["action"] == "create":
                    made = graph.send("POST", "/deviceManagement/deviceConfigurations", body)
                    pid = made.get("id")
                else:
                    pid = a["existing_id"]
                    graph.send("PATCH", f"/deviceManagement/deviceConfigurations/{pid}", body)
            results.append({**a, "result": "created" if a["action"] == "create" else "replaced", "id": pid})
        except GraphError as e:
            results.append({**a, "result": "failed", "error": str(e)})
    return results


# --------------------------------------------------------------- compliance

SCRIPT_ID = "{{DISCOVERY_SCRIPT_ID}}"


def existing_compliance(graph: GraphClient, platform: Platform) -> tuple[dict[str, str], dict[str, str]]:
    """(compliance policy name -> id, macOS discovery script name -> id)."""
    policies = {
        p.get("displayName", ""): p["id"]
        for p in graph.get_all("/deviceManagement/deviceCompliancePolicies", {"$select": "id,displayName"})
        if p.get("@odata.type") == platform.compliance_policy_type
    }
    scripts: dict[str, str] = {}
    if platform is Platform.MACOS:
        for s in graph.get_all("/deviceManagement/deviceComplianceScripts",
                               {"$select": "id,displayName,platform"}):
            if str(s.get("platform", "")).lower() == "macos":
                scripts.setdefault(s.get("displayName", ""), s["id"])
    return policies, scripts


def plan_compliance(plan: dict[str, Any], policies: dict[str, str], scripts: dict[str, str],
                    replace: list[str] | None) -> list[dict]:
    replace = set(replace or [])
    actions = []
    for p in plan["policies"]:
        pid = policies.get(p["name"])
        sid = scripts.get(p.get("script_name", "")) if p.get("script_name") else None
        if (pid or sid) and p["name"] not in replace:
            action = "skip_exists"
        elif pid or sid:
            action = "replace"
        else:
            action = "create"
        actions.append({
            "name": p["name"], "action": action, "file": p["file"],
            "built_in": len(p["builtin"]), "script_settings": p.get("settings", 0),
            **({"script_name": p["script_name"], "script_body": p["script_body"]} if p.get("script_name") else {}),
            **({"existing_policy_id": pid} if pid else {}),
            **({"existing_script_id": sid} if sid else {}),
        })
    return actions


def execute_compliance(graph: GraphClient, actions: list[dict], out_dir: Path) -> list[dict]:
    results = []
    for a in actions:
        if a["action"] not in ("create", "replace"):
            results.append({**a, "result": "skipped"})
            continue
        body = json.loads((out_dir / a["file"]).read_text(encoding="utf-8"))
        step = "discovery script"
        try:
            script_id = None
            if a.get("script_body"):
                sbody = json.loads((out_dir / a["script_body"]).read_text(encoding="utf-8"))
                if a.get("existing_script_id"):
                    script_id = a["existing_script_id"]
                    graph.send("PATCH", f"/deviceManagement/deviceComplianceScripts/{script_id}", sbody)
                else:
                    script_id = graph.send("POST", "/deviceManagement/deviceComplianceScripts", sbody).get("id")
                body["deviceCompliancePolicyScript"]["deviceComplianceScriptId"] = script_id
            step = "compliance policy"
            if a.get("existing_policy_id"):
                pid = a["existing_policy_id"]
                patch = {k: v for k, v in body.items() if k != "scheduledActionsForRule"}
                graph.send("PATCH", f"/deviceManagement/deviceCompliancePolicies/{pid}", patch)
            else:
                pid = graph.send("POST", "/deviceManagement/deviceCompliancePolicies", body).get("id")
            results.append({**a, "result": "replaced" if a["action"] == "replace" else "created",
                            "policy_id": pid, **({"script_id": script_id} if script_id else {})})
        except GraphError as e:
            results.append({**a, "result": "failed", "failed_at": step, "error": str(e)})
    return results


# -------------------------------------------------------------- remediation

SHELL_SCRIPTS = "/deviceManagement/deviceShellScripts"
CUSTOM_ATTRIBUTES = "/deviceManagement/deviceCustomAttributeShellScripts"


def existing_shell_scripts(graph: GraphClient, endpoint: str = SHELL_SCRIPTS) -> dict[str, str]:
    """macOS shell script (or custom attribute script) name -> id."""
    found: dict[str, str] = {}
    for s in graph.get_all(endpoint, {"$select": "id,displayName"}):
        found.setdefault(s.get("displayName", ""), s["id"])
    return found


def plan_remediation(plan: dict[str, Any], existing: dict[str, str], replace: list[str] | None) -> list[dict]:
    replace = set(replace or [])
    actions = []
    for s in plan["scripts"]:
        sid = existing.get(s["name"])
        action = "create" if not sid else "replace" if s["name"] in replace else "skip_exists"
        actions.append({"name": s["name"], "action": action, "file": s["file"], "rules": len(s["rules"]),
                        **({"frequency": s["frequency"]} if s.get("frequency") else {}),
                        **({"existing_id": sid} if sid else {})})
    return actions


def execute_remediation(graph: GraphClient, actions: list[dict], out_dir: Path,
                        endpoint: str = SHELL_SCRIPTS) -> list[dict]:
    results = []
    for a in actions:
        if a["action"] not in ("create", "replace"):
            results.append({**a, "result": "skipped"})
            continue
        body = json.loads((out_dir / a["file"]).read_text(encoding="utf-8"))
        try:
            extra: dict[str, Any] = {}
            if a["action"] == "replace":
                sid = a["existing_id"]
                if endpoint in SCRIPT_ONLY_ENDPOINTS:
                    graph.send("PATCH", f"{endpoint}/{sid}",
                               {k: body[k] for k in ("@odata.type", "scriptContent") if k in body})
                    extra["updated"] = "script only: Intune refuses other fields when updating custom attributes"
                else:
                    attempts = patch_with_fallback(graph, f"{endpoint}/{sid}", body)
                    if len(attempts) > 1:  # the documented body didn't work: say what did
                        extra["patch_attempts"] = attempts
            else:
                sid = graph.send("POST", endpoint, body).get("id")
            results.append({**a, "result": "replaced" if a["action"] == "replace" else "created", "id": sid, **extra})
        except GraphError as e:
            results.append({**a, "result": "failed", "error": str(e),
                            **({"patch_attempts": e.attempts} if isinstance(e, PatchFailed) else {})})
    return results


# Updating a custom attribute: Intune's docs list every field as updatable, but in a real tenant
# only {"@odata.type", "scriptContent"} was accepted. Any body that also had description,
# displayName, fileName or roleScopeTagIds (with or without name/type/runAs) got 400 "An error has
# occurred". So a replace sends only the script there; name and description stay as created.
SCRIPT_ONLY_ENDPOINTS = {CUSTOM_ATTRIBUTES}
PATCH_SHAPES: tuple[tuple[str, Any], ...] = (
    ("documented body", lambda b, i: b),
    ("script content only", lambda b, i: {k: b[k] for k in ("@odata.type", "scriptContent") if k in b}),
)


def patch_with_fallback(graph: GraphClient, path: str, body: dict[str, Any]) -> list[dict[str, Any]]:
    """PATCH the documented body; on a 400, the script content alone. Returns the attempts
    ({shape, fields, status}) ending with the one that worked; raises PatchFailed with all
    attempts when none did."""
    sid = path.rsplit("/", 1)[-1]
    attempts: list[dict[str, Any]] = []
    first: GraphError | None = None
    for label, shape in PATCH_SHAPES:
        sent = shape(body, sid)
        try:
            graph.send("PATCH", path, sent)
            attempts.append({"shape": label, "fields": sorted(sent), "status": "accepted"})
            return attempts
        except GraphError as e:
            if e.status != 400:
                raise
            first = first or e
            attempts.append({"shape": label, "fields": sorted(sent), "status": e.status})
    raise PatchFailed(str(first), attempts)


class PatchFailed(GraphError):
    def __init__(self, message: str, attempts: list[dict[str, Any]]):
        super().__init__(message, 400)
        self.attempts = attempts
