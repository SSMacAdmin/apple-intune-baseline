"""apple-intune-baseline: an MCP server over the macOS Security Compliance Project.

Phase 1 (read-only, no Graph): browse baselines and rules, explain a rule, and
get an overview of what a baseline delivers and what users will notice.

Phase 2: sign in per tenant (own app registration), tenant coverage, tailoring and
policy generation as local files. Nothing writes to Intune yet.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from functools import lru_cache
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

import json
import os
import shutil

from datetime import datetime, timezone

from . import classify, coverage, generate, layout, prefixes, push, requirements, tailoring
from .catalog import SettingDefinitions
from .auth import GraphAuth, MsalAuth
from .graph import GraphClient
from .setup import PERMISSION_SETS
from .setup import setup_app_registration as _setup_app
from .errors import UserInputError
from .mscp_source import MscpSource
from .platforms import Platform, parse_platform
from .tenants import TenantStore
from .workspace import LocalWorkspace, Workspace

mcp = MCPServer(
    "apple-intune-baseline",
    version="0.1.0",
    instructions=(
        "Works with mSCP (macOS Security Compliance Project) baselines for macOS and "
        "iOS/iPadOS and how they land in Microsoft Intune. Start with list_baselines, then "
        "baseline_overview for the big picture and explain_rule for detail. Baseline tools take "
        "platform='macos' (default) or 'ios' (iPhone and iPad). Custom compliance only "
        "exists on macOS. Generating a baseline means all of its parts, in this order: "
        "generate_policies (profiles), generate_compliance, then on macOS generate_remediation and "
        "generate_inventory; each has its own push tool. To read an Intune tenant, run setup_app_registration once per tenant "
        "(after the person approves), then sign_in. Both open a browser and may return "
        "status 'pending': ask the person to finish in the browser, then call again."
    ),
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
# Reads the person's Intune tenant through Graph; changes nothing there.
TENANT_READ = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=True)
# Creates or updates an app registration in Entra ID.
ENTRA_WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
# Changes only local config on this Mac (tenant list, sign-in state).
LOCAL_CONFIG = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
# Creates (or, when asked, replaces) policies in Intune. Never assigns or deletes.
INTUNE_WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
# Reads the tenant, writes files in the workspace; changes nothing in Intune.
LOCAL_FILES_TENANT_READ = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

TenantArg = Annotated[
    str | None, Field(description="Tenant name from add_tenant. Omit for the active tenant.")
]

PlatformArg = Annotated[str, Field(description="'macos' (default) or 'ios' for iOS/iPadOS.")]
OsVersionArg = Annotated[
    str | None, Field(description="OS version, e.g. '26.0' for macOS 26 / iOS 26 (built from mSCP's data on "
                                  "first use). Defaults to the newest mSCP ships (27.0).")
]
UnsupervisedArg = Annotated[
    bool, Field(description="The unsupervised variant: for user-enrolled, BYOD and virtual devices. Rules whose "
                "declaration needs supervision (passcode, Apple Intelligence, Siri) use their MDM payload instead "
                "where mSCP has one; names say '<OS> Unsupervised' and the set lives next to the default "
                "(supervised) one, so both can be deployed to different groups. Default false.")
]


# ---------------------------------------------------------------- app context
# Both seams are created here and only here, so a hosted mode can swap them.


@lru_cache(maxsize=1)
def _workspace() -> Workspace:
    workspace = LocalWorkspace()
    workspace.ensure()
    layout.migrate(workspace.state_dir)  # once: old generated*/ and reports/ into tenants/<tenant>/
    return workspace


def _gen_dir(tenant: str | None, ref, kind: str):
    """tenants/<tenant>/generated/<baseline>/<kind>/"""
    return layout.generated(_workspace().state_dir, _tenants().get(tenant).name, ref.name, kind)


UNSUPERVISED = "Unsupervised"
UNSUPERVISED_NOTE = ("Variant: for devices that aren't supervised (user enrollment, BYOD, VMs). Declarations that "
                     "need supervision are replaced by the rule's MDM payload where mSCP has one.")


def _variant_os(ref, unsupervised: bool) -> str:
    """The OS part of policy names: '26.0', or '26.0 Unsupervised' for the unsupervised set."""
    return f"{ref.os_version} {UNSUPERVISED}" if unsupervised else ref.os_version


def _variant_prefix(chosen: str, plat: Platform, ref, unsupervised: bool) -> str:
    """'<Prefix> - <Platform> - <Baseline> <OS>[ Unsupervised] - ': the start of one set's names."""
    return generate.policy_name(chosen, plat, tailoring.display_name(ref), _variant_os(ref, unsupervised), "", "")[:-3]


def _policies_dir(tenant: str | None, ref, unsupervised: bool):
    return _gen_dir(tenant, ref, "policies-unsupervised" if unsupervised else "policies")


def _report_dir(tenant: str | None, ref):
    """tenants/<tenant>/reports/<baseline>/"""
    return layout.reports(_workspace().state_dir, _tenants().get(tenant).name, ref.name)


@lru_cache(maxsize=1)
def _source() -> MscpSource:
    return MscpSource(_workspace())


@lru_cache(maxsize=1)
def _tenants() -> TenantStore:
    return TenantStore(_workspace().state_dir / "tenants.json")


@lru_cache(maxsize=1)
def _auth() -> GraphAuth:
    return MsalAuth(_tenants(), _workspace().state_dir / "auth")


def _graph(tenant: str | None = None) -> GraphClient:
    return GraphClient(_auth(), tenant)


# ----------------------------------------------------------------- shaping


def _summary(rule, platform: Platform, parent_values: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": rule.rule_id,
        "title": rule.title,
        "section": rule.section,
        "delivery": classify.delivery(rule),
        "verification": classify.verification(rule, platform)["status"],
    }
    value = classify.odv_value(rule, parent_values)
    if value is not None:
        out["value"] = value
    tags = classify.impact_tags(rule)
    if tags:
        out["impact"] = tags
    return out


def _load(baseline: str, platform: Platform, os_version: str | None):
    src = _source()
    ref = src.resolve(baseline, platform, os_version)
    return ref, src.load(ref)


# ------------------------------------------------------------------- tools


@mcp.tool(annotations=READ_ONLY)
def workspace_status() -> dict[str, Any]:
    """Show which mSCP release is pinned, where tailored baselines are stored, and sign-in state."""
    src = _source()
    return {
        "mscp_version": src.mscp_version,
        "workspace": src.workspace.describe(),
        "graph": _auth().status(),
        "platforms": {p.value: p.display for p in Platform},
        "latest_os": {p.value: src.latest_os_version(p) for p in Platform},
        "os_versions": {p.value: src.supported_versions(p) for p in Platform},
    }


# ------------------------------------------------------------- tenants & auth

@mcp.tool(annotations=ENTRA_WRITE)
def setup_app_registration(
    confirm: Annotated[
        Literal[True], Field(description="Must be true: the person approved creating the app registration.")
    ],
    display_name: Annotated[str, Field(description="App registration name in Entra.")] = "apple-intune-baseline MCP",
    connection_name: Annotated[
        str | None, Field(description="Local name for the tenant. Defaults to its default domain's first label.")
    ] = None,
    permission_set: Annotated[
        Literal["readOnly", "full"],
        Field(
            description=f"readOnly: {', '.join(PERMISSION_SETS['readOnly'])}. "
            f"full: {', '.join(PERMISSION_SETS['full'])} (only needed to push policies later)."
        ),
    ] = "readOnly",
    restrict_to_me: Annotated[
        bool, Field(description="Require user assignment and assign only the admin signing in.")
    ] = True,
    grant_admin_consent: Annotated[
        bool, Field(description="Grant tenant-wide consent (needs Global Admin or Privileged Role Admin).")
    ] = True,
) -> dict[str, Any]:
    """One-time setup per tenant, like mac-packager: signs in with Microsoft Graph PowerShell's
    public client (as Connect-MgGraph does) and creates a single-tenant, public-client app
    registration with delegated Graph permissions, its Enterprise App, optional user assignment
    and admin consent, then saves the tenant locally. The setup tokens stay in memory and are
    dropped afterwards. Safe to re-run: an app with the same name is updated, not duplicated.
    Writes to Entra ID, so explain what it creates and get the person's approval first. If it
    returns status 'pending', the person is still signing in: call it again with the same
    arguments once they are done."""
    return _setup_app(
        _auth(), _tenants(), display_name, connection_name, permission_set, restrict_to_me, grant_admin_consent
    )


@mcp.tool(annotations=LOCAL_CONFIG)
def add_tenant(
    name: Annotated[str, Field(description="Short name, e.g. 'MacAdmin' or 'Contoso'.")],
    tenant_id: Annotated[str, Field(description="Directory (tenant) ID GUID or domain.")],
    client_id: Annotated[str, Field(description="Application (client) ID of the app registration.")],
    permission_set: Annotated[
        Literal["readOnly", "full"],
        Field(
            description=f"What the app registration was granted. readOnly: {', '.join(PERMISSION_SETS['readOnly'])}. "
            f"full: {', '.join(PERMISSION_SETS['full'])} (needed to push)."
        ),
    ] = "readOnly",
) -> dict[str, Any]:
    """Manual alternative to setup_app_registration, for an app registration that already
    exists: save its tenant and client ID on this Mac and make it the active tenant. The app
    must be a public client with redirect URI http://localhost and the delegated permissions of
    its permission set (admin consented). Stores only IDs, no secrets."""
    t = _tenants().add(name, tenant_id, client_id, permission_set=permission_set)
    return {"saved": t.name, "active": True, "permission_set": t.permission_set,
            "next": "Call sign_in to sign in to this tenant."}


@mcp.tool(annotations=READ_ONLY)
def list_tenants() -> dict[str, Any]:
    """Configured tenants, which one is active, and who is signed in to each."""
    return _auth().status()


@mcp.tool(annotations=LOCAL_CONFIG)
def use_tenant(name: Annotated[str, Field(description="Tenant name from add_tenant.")]) -> dict[str, Any]:
    """Switch the active tenant. Later tenant tools use it unless they name another."""
    return {"active": _tenants().use(name).name}


@mcp.tool(annotations=LOCAL_CONFIG)
def sign_in(tenant: TenantArg = None) -> dict[str, Any]:
    """Sign in to a tenant with its own app registration. Uses the cached sign-in when there is
    one; otherwise opens the browser on this Mac. Returns status 'pending' if the person is still
    signing in after about 45 seconds: ask them to finish in the browser, then call again."""
    return _auth().sign_in(tenant)


@mcp.tool(annotations=LOCAL_CONFIG)
def sign_out(tenant: TenantArg = None) -> dict[str, Any]:
    """Remove the cached sign-in for a tenant from this Mac."""
    return _auth().sign_out(tenant)


@mcp.tool(annotations=TENANT_READ)
def check_connection(tenant: TenantArg = None) -> dict[str, Any]:
    """Prove the sign-in works: count the tenant's Settings Catalog policies for macOS and
    iOS/iPadOS. Read-only."""
    g = _graph(tenant)
    counts = {}
    for plat, flt in (("macos", "macOS"), ("ios", "iOS")):
        items = g.get_all(
            "/deviceManagement/configurationPolicies",
            {"$select": "id", "$filter": f"platforms has '{flt}'"},
        )
        counts[plat] = len(items)
    return {
        "tenant": _tenants().get(tenant).name,
        "connected": True,
        "settings_catalog_policies": counts,
    }


COVERAGE_LABELS = {
    "covered_assigned": "Configured with the baseline value in an assigned policy",
    "covered_unassigned": "Configured with the baseline value, but the policy is not assigned",
    "partial": "Some of the rule's settings are configured, others are missing",
    "conflict": "Configured with a different value than the baseline",
    "duplicate": "Configured in more than one policy (Intune reports this as a conflict)",
    "configured_unverified_value": "Configured, but the value has a shape the check can't compare",
    "not_configured": "Not configured; a Settings Catalog setting exists for it",
    "not_configured_custom_profile_only": "Not configured; no Settings Catalog setting, needs a custom profile",
}
VERIFICATION_LABELS = {
    "verified_assigned": "Checked by an assigned compliance policy (built-in setting or custom script)",
    "verified_unassigned": "Checked by a compliance policy that is not assigned",
    "compliance_different_value": "A compliance policy checks it, with a weaker value than the baseline",
    "not_verified": "No compliance policy checks it (Intune has a built-in setting for it)",
}
ATTENTION = {"conflict", "duplicate", "partial", "configured_unverified_value"}


def _found(f: dict) -> str:
    return f"{f['name']} ({f['assignment']}): {f['value']}"


@mcp.tool(annotations=TENANT_READ)
def check_tenant_coverage(
    baseline: Annotated[str, Field(description="Baseline key, e.g. 'cis_lvl1'.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    rule: Annotated[
        str | None, Field(description="Only this rule ID, with full per-setting detail.")
    ] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Which of a baseline's rules the tenant already enforces (Settings Catalog policies and
    custom profiles) and verifies (built-in compliance policy settings), in which policies,
    with which values, and whether those policies are assigned. Every policy for the platform
    is checked, assigned or not. Read-only.

    Present 'enforcement' and 'verification' as tables, 'needs_attention' as a list, and
    'policies' as a table of what each policy contributes. Call again with rule=... for
    one rule's detail."""
    plat = parse_platform(platform)
    ref, base = _load(baseline, plat, os_version)
    scan = coverage.fetch_policies(_graph(tenant), plat)
    parent = getattr(base, "parent_values", "") or ""
    checks = coverage.COMPLIANCE_CHECKS[plat]
    scripted = {str(r["SettingName"]).lower() for p in scan.compliance for r in p.props.get("_script_rules", [])}

    rules = [
        r for p in base.profile for r in p.rules
        if classify.delivery(r) in ("ddm", "profile") or r.rule_id in checks or r.rule_id.lower() in scripted
    ]
    if rule:
        rules = [r for r in rules if r.rule_id == rule]
        if not rules:
            raise UserInputError(
                f"'{rule}' is not a profile, DDM or built-in compliance rule in {ref.name}, and no "
                "custom compliance script checks it. Script and manual rules have no policy settings "
                "to look for."
            )

    enforcement: dict[str, list[str]] = defaultdict(list)
    verification: dict[str, list[str]] = defaultdict(list)
    attention: list[dict[str, Any]] = []
    contributes: dict[tuple[str, str], list[str]] = defaultdict(list)
    detail: dict[str, Any] = {}

    for r in rules:
        if classify.delivery(r) in ("ddm", "profile"):
            res = coverage.rule_coverage(r, scan.config)
            if res["status"] != "not_applicable":
                enforcement[res["status"]].append(r.rule_id)
                detail["enforcement"] = res
                names = set()
                for s in res["settings"]:
                    for f in s["found_in"]:
                        if f.get("matches") is not False:
                            names.add((f["name"], f["kind"]))
                for key in names:
                    contributes[key].append(r.rule_id)
                if res["status"] in ATTENTION:
                    attention.append({
                        "rule": r.rule_id,
                        "status": res["status"],
                        "settings": [
                            {"setting": s["setting"], "expected": s["expected"],
                             "found": [_found(f) for f in s["found_in"]] or ["not set anywhere"]}
                            for s in res["settings"] if not s["status"].startswith("covered")
                        ],
                    })
        ver = coverage.rule_verification(r.rule_id, plat, classify.odv_value(r, parent), scan.compliance)
        if ver:
            verification[ver["status"]].append(r.rule_id)
            detail["verification"] = ver
            for f in ver["found_in"]:
                if f["meets_baseline"]:
                    contributes[(f["name"], f["kind"])].append(r.rule_id)
            if ver["status"] == "compliance_different_value":
                attention.append({
                    "rule": r.rule_id,
                    "status": "compliance_different_value",
                    "settings": [{"setting": ver.get("compliance_setting", "custom compliance script"),
                                  "expected": ver.get("baseline_value", "enabled"),
                                  "found": [_found(f) for f in ver["found_in"]]}],
                })

    out: dict[str, Any] = {
        "tenant": _tenants().get(tenant).name,
        "baseline": ref.name,
        "platform": plat.display,
        "policies_scanned": scan.counts(),
    }
    every = scan.config + scan.compliance
    if rule:
        involved = {f["name"] for part in detail.values()
                    for f in (part.get("found_in") or [x for s in part.get("settings", []) for x in s["found_in"]])}
        out["rule"] = rule
        out.update(detail)
        out["policies"] = [
            {"name": p.name, "kind": p.kind, "assignment": p.assignment["state"]}
            for p in every if p.name in involved
        ] or "No policy in the tenant sets this rule."
    else:
        out["rules_checked"] = {
            "enforcement": sum(map(len, enforcement.values())),
            "verification": sum(map(len, verification.values())),
        }
        out["enforcement"] = {
            k: {"label": COVERAGE_LABELS[k], "count": len(enforcement[k]), "rules": enforcement[k]}
            for k in COVERAGE_LABELS if enforcement.get(k)
        }
        out["verification"] = {
            k: {"label": VERIFICATION_LABELS[k], "count": len(verification[k]), "rules": verification[k]}
            for k in VERIFICATION_LABELS if verification.get(k)
        }
        if attention:
            out["needs_attention"] = attention
        out["policies"] = [
            {"name": p.name, "kind": p.kind, "assignment": p.assignment["state"],
             "baseline_rules": sorted(set(contributes[(p.name, p.kind)]))}
            for p in every if contributes.get((p.name, p.kind))
        ]
        out["other_policies"] = [
            f"{p.name} ({p.kind.replace('_', ' ')}, {p.assignment['state']})"
            for p in every if not contributes.get((p.name, p.kind))
        ]
    excluded = (tailoring.read_tailoring(ref).get("excluded") or {}) if not rule else {}
    if excluded:
        by_reason: dict[str, list[str]] = defaultdict(list)
        for rid, why in excluded.items():
            by_reason[why or "no reason given"].append(rid)
        # Rules the person left out on purpose; not gaps, and not checked here.
        out["excluded_by_tailoring"] = [
            {"reason": why, "count": len(ids), "rules": sorted(ids)} for why, ids in by_reason.items()
        ]
    out["notes"] = scan.notes + [
        "Script and manual rules are not policy settings; see baseline_overview for those."
    ] + (["Rules in excluded_by_tailoring were left out of this tailored baseline on purpose; "
          "they are not gaps."] if excluded else [])
    return out


def _settings_file():
    return _workspace().state_dir / "settings.json"


def _settings() -> dict[str, Any]:
    try:
        return json.loads(_settings_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_settings(data: dict[str, Any]) -> None:
    f = _settings_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _save_setting(key: str, value: Any) -> None:
    data = _settings()
    data[key] = value
    _write_settings(data)


def _prefixes() -> dict[str, Any]:
    """Settings, with the old single prefix migrated to per-baseline prefixes (once)."""
    data = _settings()
    moved = prefixes.migrate(data, _workspace().state_dir, _tenants().active_name)
    if prefixes.migrate_values(data) or moved:
        _write_settings(data)
    return data


def _prefix(tenant: str | None, plat: Platform, ref, given: str | None, *, creating: bool
            ) -> tuple[str, dict[str, Any]]:
    """Prefix for this tenant, platform and baseline, and how it was chosen (shown in results)."""
    data = _prefixes()
    chosen, info = prefixes.resolve(data, _tenants().get(tenant).name, plat, ref.key, given, creating=creating)
    if creating and (given or "").strip():
        _write_settings(data)
    return chosen, info


def _drop_other_baselines(policies: list, tenant: str | None, plat: Platform) -> tuple[list, list[str]]:
    """Leave out this tool's policies for other baselines (by their saved prefixes), so baselines
    evaluated side by side don't count each other as coverage."""
    pattern = prefixes.tool_names(_prefixes(), _tenants().get(tenant).name, plat, plat.mscp_os)
    if pattern is None:
        return policies, []
    return ([p for p in policies if not pattern.match(p.name)],
            sorted(p.name for p in policies if pattern.match(p.name)))


BUILTIN_MIX_NOTE = (
    "include_builtin: some policies combine Intune's built-in settings with a discovery script. Built-in "
    "password settings make Intune ask users for a new password, and a user-enrolled macOS 26 Mac was seen "
    "ignoring the script part of such a policy (reporting compliant on the built-in settings alone). The "
    "default (include_builtin unset) checks everything in the script.")


OTHER_BASELINES_NOTE = (
    "Policies this tool made for other baselines here (other_baselines_not_counted) don't count as "
    "coverage, so baselines can be evaluated side by side. Assign them to different groups; to layer "
    "baselines on the same Macs instead, generate with count_other_baselines=true.")


@mcp.tool(annotations=LOCAL_CONFIG)
def name_prefixes(
    baseline: Annotated[str | None, Field(description="Baseline key to save or remove a prefix for.")] = None,
    prefix: Annotated[str | None, Field(description="Prefix to save for that baseline, e.g. 'NIST TST'.")] = None,
    remove: Annotated[bool, Field(description="Remove the saved prefix for that baseline.")] = False,
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
) -> dict[str, Any]:
    """List the saved name prefixes (and each baseline's saved required values), or save/remove a
    prefix. Prefixes are per tenant, platform and
    baseline, so one tenant can hold e.g. 'CIS TST - macOS - CIS L1 ...' and 'NIST TST - macOS -
    NIST 800-53 Moderate ...' side by side. Renaming here doesn't rename anything in Intune:
    objects pushed with the old prefix keep their names. Without arguments, lists all."""
    data = _prefixes()
    changed: dict[str, Any] = {}
    if baseline:
        plat = parse_platform(platform)
        ref, _ = _load(baseline, plat, None)
        t = _tenants().get(tenant).name
        if remove:
            changed = {"removed": prefixes.forget(data, t, plat, ref.key), "baseline": ref.key, "tenant": t,
                       "platform": plat.display}
        elif (prefix or "").strip():
            old = prefixes.remember(data, t, plat, ref.key, prefix.strip())
            changed = {"saved": prefix.strip(), "baseline": ref.key, "tenant": t, "platform": plat.display,
                       **({"replaced": old,
                           "note": f"Objects already pushed as '{old} - …' keep that name; pass prefix='{old}' "
                                   "to read their results."} if old else {})}
        else:
            raise UserInputError("Pass prefix=... to save, or remove=true.")
        _write_settings(data)
    elif prefix or remove:
        raise UserInputError("Say which baseline (baseline=...).")
    names = {"macos": "macOS", "ios": "iOS/iPadOS"}
    return {
        **changed,
        "prefixes": {t: {names.get(pk, pk): dict(sorted(b.items())) for pk, b in plats.items() if b}
                     for t, plats in sorted(prefixes.table(data).items()) if any(plats.values())},
        **({"saved_values": {t: {names.get(pk, pk): dict(sorted(b.items())) for pk, b in plats.items() if b}
                             for t, plats in sorted(data["baseline_values"].items()) if any(plats.values())}}
           if data.get("baseline_values") else {}),
        **({"legacy_prefix": data["legacy_prefix"]} if data.get("legacy_prefix") else {}),
    }


PLAN_NEXT = (
    "Show this plan to the person and stop. Call again with confirm=true only after they reply yes "
    "to this plan, even when their request already asked for the push: they decide on the plan, "
    "not on the request."
)


@mcp.tool(annotations=LOCAL_CONFIG)
def tailor_baseline(
    name: Annotated[str, Field(description="Short name for the tailored baseline, e.g. 'contoso_cis_lvl1'.")],
    from_baseline: Annotated[
        str | None, Field(description="mSCP baseline to start from, e.g. 'cis_lvl1'. Only when creating.")
    ] = None,
    platform: PlatformArg = "macos",
    os_version: OsVersionArg = None,
    exclude: Annotated[list[str] | None, Field(description="Rule IDs to leave out.")] = None,
    include: Annotated[
        list[str] | None, Field(description="Rule IDs to add (from any mSCP baseline) or bring back.")
    ] = None,
    values: Annotated[
        dict[str, Any] | None,
        Field(description="New organization-defined values, rule ID -> value, e.g. {'pwpolicy_minimum_length_enforce': 12}."),
    ] = None,
    reset_values: Annotated[
        list[str] | None, Field(description="Rule IDs whose value goes back to the baseline's.")
    ] = None,
    reason: Annotated[str | None, Field(description="Why rules are excluded; kept with the baseline.")] = None,
    display_name: Annotated[
        str | None, Field(description="Short name used in Intune policy names, e.g. 'CIS L1 Contoso'.")
    ] = None,
) -> dict[str, Any]:
    """Create or change a tailored copy of an mSCP baseline in the workspace: leave rules out
    (with a reason), add rules, or change organization-defined values (password length, screen
    saver timeout...). Saved in mSCP's own format; the original baseline is untouched. Use the
    tailored name with every other tool afterwards. Show the person what will change and get a
    yes before calling.

    The same tailored baseline for another OS version (e.g. macOS 26 next to 27): call with the
    name and os_version only. Its exclusions and added rules are copied onto mSCP's version of the
    same source baseline; values are shared already. Rules that don't exist on that OS are listed.
    Tailored baselines are stored per OS version, so 26 and 27 can then be changed separately."""
    plat = parse_platform(platform)
    return tailoring.tailor(
        _source(), plat, name, from_baseline, os_version, exclude, include, values,
        reset_values, reason, display_name,
    )


@mcp.tool(annotations=LOCAL_FILES_TENANT_READ)
def generate_policies(
    baseline: Annotated[str, Field(description="Baseline key, mSCP or tailored, e.g. 'cis_lvl1'.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    prefix: Annotated[str | None, Field(description="Name prefix, e.g. 'CIS TST'. Saved per tenant, platform and baseline; ask the person when none is saved.")] = None,
    sections: Annotated[
        list[str] | None, Field(description="Only these mSCP sections, e.g. ['System Settings'].")
    ] = None,
    skip_configured: Annotated[
        bool, Field(description="Skip rules the tenant already configures (default true).")
    ] = True,
    count_other_baselines: Annotated[
        bool, Field(description="Count policies this tool made for other baselines in this tenant as coverage. "
                    "Default false: baselines stay apart, e.g. CIS and NIST evaluated side by side.")
    ] = False,
    required_values: Annotated[
        dict[str, Any] | None,
        Field(description="Values for settings Intune requires that have no sensible default, "
              "setting ID -> value, e.g. {'com.apple.screensaver_modulename': 'Flurry'}. Saved for this "
              "baseline (per tenant and platform); other baselines don't inherit it."),
    ] = None,
    os_version: OsVersionArg = None,
    unsupervised: UnsupervisedArg = False,
) -> dict[str, Any]:
    """Build the Intune policies for a baseline as local files for review: per mSCP section one
    Settings Catalog policy (DDM included) and, only where the catalog can't express a rule, one
    custom profile. Rules the tenant already configures are skipped and listed with the policy
    that has them; rules set to a different value are left for the person to fix. Names follow
    '<Prefix> - <Platform> - <Baseline> <OS> - <Section> - <Type>'. Nothing is sent to Intune.

    Prefixes are saved per tenant, platform and baseline; if none is saved for this one, ask the
    person (suggest the ones already used there). Say which prefix was used. Present the result
    as a table of policies (name, rules, settings count), then skipped, needs attention and not
    deliverable. If device_requirements is present, say plainly which rules need a newer OS
    point release or a supervised device: devices that don't meet them report 'Not applicable'.
    For devices that aren't supervised (user enrollment, BYOD, VMs), offer unsupervised=true: a
    separate set named '<Baseline> <OS> Unsupervised', next to the default (supervised) set, for
    other groups. Always pass on heads_up: those payloads need configuration before pushing."""
    plat = parse_platform(platform)
    ref, base = _load(baseline, plat, os_version)
    chosen, prefix_info = _prefix(tenant, plat, ref, prefix, creating=True)
    tname = _tenants().get(tenant).name
    data = _prefixes()
    remembered = {**prefixes.values(data, tname, plat, ref.key), **(required_values or {})}
    if required_values:
        prefixes.save_values(data, tname, plat, ref.key, required_values)
        _write_settings(data)
    graph = _graph(tenant)
    scan = coverage.fetch_policies(graph, plat) if skip_configured else None
    # Policies this baseline generated before (same name pattern) are ours to replace, not
    # coverage: otherwise a second run would skip every rule they already hold.
    own_prefix = _variant_prefix(chosen, plat, ref, unsupervised)
    sibling = _variant_prefix(chosen, plat, ref, not unsupervised)
    own, sibling_set = [], []
    if scan is not None:
        own = sorted(p.name for p in scan.config if p.name.startswith(own_prefix))
        # the other variant of this baseline is meant for other devices: not coverage either
        sibling_set = sorted(p.name for p in scan.config if p.name.startswith(sibling))
        scan.config = [p for p in scan.config if not p.name.startswith((own_prefix, sibling))]
    other: list[str] = []
    if scan is not None and not count_other_baselines:
        scan.config, other = _drop_other_baselines(scan.config, tenant, plat)
    defs = SettingDefinitions(graph, _workspace().state_dir / "settings_catalog_definitions.json")
    known_sections = [p.section for p in base.profile]
    if sections:
        unknown = [s for s in sections if s not in known_sections]
        if unknown:
            raise UserInputError(f"Unknown section(s) {unknown}. This baseline has: {', '.join(known_sections)}")
    try:
        result = generate.build(base, plat, defs, scan, sections, remembered, os_version=ref.os_version,
                                unsupervised=unsupervised)
        out_dir = _policies_dir(tenant, ref, unsupervised)
        policies = generate.write(
            result, out_dir, prefix=chosen, platform=plat,
            baseline_display=tailoring.display_name(ref), baseline_name=ref.name,
            os_version=ref.os_version, mscp_version=_source().mscp_version,
            name_os=_variant_os(ref, unsupervised),
            variant_note=UNSUPERVISED_NOTE if unsupervised else "",
        )
    finally:
        defs.save()
    # a saved value for a setting this baseline sets itself never applies (the baseline wins): drop it
    data = _prefixes()
    unused = prefixes.drop_values(data, tname, plat, ref.key, result["baseline_sets"])
    if unused:
        _write_settings(data)
    for p in policies:
        for a in p.get("added_because_intune_requires", []):
            if a.get("needs_value"):
                result["attention"].append({
                    "policy": p["name"], "setting": a["setting"], "status": "needs_value",
                    "why": "Intune requires this setting alongside the baseline's, and its default is empty. "
                           "Ask the person for a value, then call again with required_values={setting: value}.",
                })
    device_reqs = [r for p in policies for r in p.get("device_requirements", [])]
    policy_of = {r: p["name"] for p in policies for r in p["rules"]}
    heads_up = [{**h, "policy": policy_of.get(h["rule"].split(", ")[0], "")} for h in result["heads_up"]]
    switched = [{**w, "policy": policy_of.get(w["rule"], "")} for w in result["switched_to_profile"]]
    gone = sorted(set(own) - {p["name"] for p in policies})
    (out_dir / "plan.json").write_text(json.dumps({
        "baseline": ref.name, "platform": plat.display, "prefix": chosen, "policies": policies,
        "own_prefix": own_prefix,
        "device_requirements": device_reqs, "heads_up": heads_up,
        "variant": "unsupervised" if unsupervised else "supervised",
        "switched_to_profile": switched,
        "tenant": _tenants().get(tenant).name, "generated_at": datetime.now(timezone.utc).isoformat(),
        "skip_configured": skip_configured,
        "skipped": result["skipped"], "needs_attention": result["attention"],
        "not_deliverable": result["undeliverable"], "not_policy_rules": result["not_policy"],
        "merged_lists": result["merged_lists"],
    }, indent=2, default=str), encoding="utf-8")
    np = result["not_policy"]
    notes = []
    if own:
        notes.append(
            f"{len(own)} policies from an earlier run of this baseline are in the tenant; they don't count "
            "as coverage. Push with replace=[their names] to update them."
        )
    if gone:
        notes.append(
            f"{len(gone)} of them aren't part of this run any more (no_longer_generated), e.g. a section's "
            "settings moved to a custom profile: replacing doesn't touch them, so they keep applying their old "
            "settings. Tell the person to delete or unassign them in Intune."
        )
    if other:
        notes.append(OTHER_BASELINES_NOTE)
    if unused:
        notes.append(f"Removed saved value(s) for {', '.join(unused)}: this baseline sets them itself, and its "
                     "own value always wins.")
    if result["merged_lists"]:
        notes.append("List keys several rules add to (merged_lists) are in one custom profile only, with every "
                     "rule's items, as mSCP does it: two profiles setting the same key don't combine on a Mac.")
    notes += requirements.summary(plat, ref.os_version, device_reqs)
    if unsupervised:
        dep = sorted({w["deprecated_in"] for w in switched if w.get("deprecated_in")})
        notes.append("Unsupervised variant: names end the OS part with 'Unsupervised', files are in "
                     f"{out_dir.name}/. " + (
                         f"{len(switched)} rule(s) use their MDM payload instead of a declaration that needs "
                         "supervision, so they also apply on unsupervised devices"
                         + (f"; Apple has deprecated some of those keys ({plat.display} {', '.join(dep)}), so they "
                            "may stop working in a later release" if dep else "") + "."
                         if switched else "No rule here has an MDM payload that avoids supervision.")
                     + " Assign this set and the supervised one to different groups.")
    if sibling_set:
        notes.append(f"The {'supervised' if unsupervised else 'unsupervised'} variant of this baseline is in the "
                     "tenant too (other_variant_not_counted); it doesn't count as coverage. Assign the two to "
                     "different groups (e.g. ADE Macs and the rest).")
    if heads_up:
        notes.append(f"Heads up: {len(heads_up)} rule(s) need configuration before pushing (heads_up): "
                     + "; ".join(sorted({h['payload'] for h in heads_up})) + ".")
    if not skip_configured:
        notes.append("Tenant coverage was not checked; rules may duplicate existing policies.")
    if np.get("script"):
        notes.append(
            f"{len(np['script'])} script rules have no policy setting: generate_compliance checks them and "
            "generate_remediation enforces them." if plat.supports_custom_compliance else
            f"{len(np['script'])} script rules can't be enforced or checked by Intune on iOS/iPadOS."
        )
    next_step = (
        "These are the profiles, one of four parts of the baseline. Offer the rest for the same baseline: "
        "generate_compliance (checks every rule with mSCP's own checks), generate_remediation (shell scripts "
        "for the rules no policy can enforce) and generate_inventory (raw values per Mac, for a CMDB)."
        if plat.supports_custom_compliance else
        "These are the profiles. Offer generate_compliance for the same baseline too (Intune's built-in "
        "compliance settings); remediation and inventory scripts are macOS only."
    )
    return {
        "baseline": ref.name,
        "platform": plat.display,
        "tenant": _tenants().get(tenant).name,
        **prefix_info,
        "output_folder": str(out_dir),
        "policies": [
            {k: v for k, v in p.items() if k not in ("file", "mobileconfig", "device_requirements")}
            | {"settings_count": len(p["settings"])}
            for p in policies
        ],
        **({"device_requirements": [{k: r[k] for k in ("rule", "policy", "requirement")} for r in device_reqs]}
           if device_reqs else {}),
        **({"switched_to_profile": [{k: w[k] for k in ("rule", "policy", "declaration", "instead")}
                                    for w in switched]} if switched else {}),
        **({"heads_up": [{k: h[k] for k in ("rule", "policy", "note")} for h in heads_up]} if heads_up else {}),
        "skipped_already_configured": result["skipped"],
        **({"own_policies_not_counted": own} if own else {}),
        **({"no_longer_generated": gone} if gone else {}),
        **({"other_variant_not_counted": sibling_set} if sibling_set else {}),
        **({"other_baselines_not_counted": other} if other else {}),
        "needs_attention": result["attention"],
        "not_deliverable": result["undeliverable"],
        **({"merged_lists": [{k: m[k] for k in ("payload", "key", "section", "rules")}
                             for m in result["merged_lists"]]} if result["merged_lists"] else {}),
        "not_policy_rules": {k: len(v) for k, v in np.items()},
        "notes": notes + ["Files only: nothing was sent to Intune. Review them, then push in a later step."],
        "next": next_step,
    }


@mcp.tool(annotations=LOCAL_FILES_TENANT_READ)
def generate_compliance(
    baseline: Annotated[str, Field(description="Baseline key, mSCP or tailored, e.g. 'cis_lvl1'.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    prefix: Annotated[str | None, Field(description="Name prefix, e.g. 'CIS TST'. Saved per tenant, platform and baseline; ask the person when none is saved.")] = None,
    sections: Annotated[list[str] | None, Field(description="Only these mSCP sections.")] = None,
    include_per_user: Annotated[
        bool, Field(description="Also check settings read from the last logged-in user (default false).")
    ] = False,
    merge: Annotated[
        list[str] | None,
        Field(description="Sections whose script checks become one setting listing the failing rules. "
              "Default ['Auditing']; [] for one setting per rule everywhere."),
    ] = None,
    include_builtin: Annotated[
        bool | None, Field(description="Use Intune's built-in compliance settings (password, firewall, SIP...) "
                           "where one exists. Default: false on macOS (every check is mSCP's own check in the "
                           "discovery script, a read-only report), true on iOS/iPadOS (no custom compliance). "
                           "On macOS, built-in password settings make Intune ask the user for a new password, and "
                           "some Macs ignore the script part of a policy that also has built-in settings.")
    ] = None,
    skip_verified: Annotated[
        bool, Field(description="Skip rules a compliance policy in the tenant already checks (default true).")
    ] = True,
    count_other_baselines: Annotated[
        bool, Field(description="Count policies this tool made for other baselines in this tenant as coverage. "
                    "Default false: baselines stay apart, e.g. CIS and NIST evaluated side by side.")
    ] = False,
    grace_period_hours: Annotated[
        int, Field(description="Hours before a failing Mac is marked non-compliant (default 0).")
    ] = 0,
    more_info_url: Annotated[
        str | None, Field(description="Link shown with each failing check in Company Portal. Remembered.")
    ] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Build selective compliance for a baseline as local files for review: per mSCP section one
    compliance policy with one discovery script (mSCP's own checks, read-only) plus its rules JSON.
    On macOS every check is in the script by default, also those Intune has a built-in setting for
    (include_builtin=true to use those; on iOS/iPadOS only built-in settings exist). Rules the tenant
    already verifies are skipped; per-user checks are left out unless asked; Auditing checks are
    merged into one setting by default. Nothing is sent to Intune.

    Present the result as a table per policy (built-in, script checks, merged), then skipped with
    reasons. custom compliance is macOS only; on iOS/iPadOS only built-in settings apply."""
    from . import compliance

    plat = parse_platform(platform)
    ref, base = _load(baseline, plat, os_version)
    chosen, prefix_info = _prefix(tenant, plat, ref, prefix, creating=True)
    if more_info_url:
        _save_setting("more_info_url", more_info_url)
    more_info = more_info_url or _settings().get("more_info_url") or compliance.DEFAULT_MORE_INFO
    scan = coverage.fetch_policies(_graph(tenant), plat) if skip_verified else None
    own_prefix = generate.policy_name(chosen, plat, tailoring.display_name(ref), ref.os_version, "", "")[:-3]
    own = []
    if scan is not None:
        own = sorted(p.name for p in scan.compliance if p.name.startswith(own_prefix))
        scan.compliance = [p for p in scan.compliance if not p.name.startswith(own_prefix)]
    other: list[str] = []
    if scan is not None and not count_other_baselines:
        scan.compliance, other = _drop_other_baselines(scan.compliance, tenant, plat)
    if include_builtin is None:
        include_builtin = not plat.supports_custom_compliance
    result = compliance.select(base, plat, scan, sections=sections, include_per_user=include_per_user,
                               merge=merge, include_builtin=include_builtin)
    out_dir = _gen_dir(tenant, ref, "compliance")
    policies = compliance.write(
        result, out_dir, prefix=chosen, platform=plat, baseline_display=tailoring.display_name(ref),
        baseline_name=ref.name, os_version=ref.os_version, mscp_version=_source().mscp_version,
        more_info=more_info, grace_hours=grace_period_hours,
    )
    (out_dir / "plan.json").write_text(json.dumps({
        "baseline": ref.name, "platform": plat.display, "prefix": chosen,
        "tenant": _tenants().get(tenant).name, "generated_at": datetime.now(timezone.utc).isoformat(),
        "policies": policies, "skipped": result["skipped"], "needs_attention": result["attention"],
    }, indent=2, default=str), encoding="utf-8")
    counts = {
        "built_in": sum(len(p["builtin"]) for p in policies),
        "script_settings": sum(p.get("settings", 0) for p in policies),
        "script_checks": sum(len(p["script_checks"]) + len(p["merged_checks"]) for p in policies),
        "skipped": len(result["skipped"]),
    }
    return {
        "baseline": ref.name, "platform": plat.display, **prefix_info, "output_folder": str(out_dir),
        "policies": [{k: v for k, v in p.items() if k not in ("file", "script", "rules_json")} for p in policies],
        "counts": counts,
        "skipped": result["skipped"],
        "needs_attention": result["attention"],
        **({"own_policies_not_counted": own} if own else {}),
        **({"other_baselines_not_counted": other} if other else {}),
        "notes": ([OTHER_BASELINES_NOTE] if other else []) + [
            "Files only: nothing was sent to Intune. Each .sh can be tested on a Mac first: "
            "sudo env -i /bin/bash <file>.sh should print one line of JSON.",
            f"Failing Macs are marked non-compliant after {grace_period_hours} hours.",
        ] + ([BUILTIN_MIX_NOTE] if include_builtin and plat.supports_custom_compliance and any(
            p["builtin"] and (p["script_checks"] or p["merged_checks"]) for p in policies) else []),
    }


@mcp.tool(annotations=INTUNE_WRITE)
def push_policies(
    baseline: Annotated[str, Field(description="Baseline key whose generated policies to push, e.g. 'cis_lvl1'.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    confirm: Annotated[
        bool,
        Field(description="False (default): only show what would happen. True: create the policies. "
              "Only after the person said yes to the plan."),
    ] = False,
    replace: Annotated[
        list[str] | None,
        Field(description="Names of existing policies to overwrite with the generated version. "
              "Only when the person explicitly asked for that."),
    ] = None,
    only: Annotated[
        list[str] | None, Field(description="Push only these generated policy names.")
    ] = None,
    os_version: OsVersionArg = None,
    unsupervised: Annotated[bool, Field(description="Push the unsupervised variant generate_policies wrote "
                                                    "(unsupervised=true there). Default: the supervised set.")] = False,
) -> dict[str, Any]:
    """Create the policies generate_policies wrote for a baseline in Intune, unassigned. Call
    first without confirm and show the person the plan (what is created, skipped because the name
    exists, or replaced); call again with confirm=true only after they say yes. Existing policies
    are never touched unless named in replace. Nothing is assigned or deleted.

    The plan compares each existing policy with the generated one (in_intune: same / differs).
    After regenerating, offer to replace every policy that differs, not only the ones asked about."""
    plat = parse_platform(platform)
    ref, _ = _load(baseline, plat, os_version)
    out_dir = _policies_dir(tenant, ref, unsupervised)
    plan = push.load_plan(out_dir)
    generated = {p["name"] for p in plan["policies"]}
    if only:
        names = {p["name"] for p in plan["policies"]}
        unknown = [n for n in only if n not in names]
        if unknown:
            raise UserInputError(f"Not in the generated set: {', '.join(unknown)}")
        plan = {**plan, "policies": [p for p in plan["policies"] if p["name"] in only]}
    t = _tenants().get(tenant)
    problems = push.blockers(plan, t.name, t.permission_set)
    graph = _graph(tenant)
    existing = push.existing_policies(graph, plat)
    actions = push.plan_actions(plan, existing, replace)
    leftover = push.no_longer_generated(existing, plan.get("own_prefix"), generated)
    out: dict[str, Any] = {
        "baseline": ref.name, "platform": plat.display, "tenant": t.name,
        "generated_at": plan.get("generated_at"),
        "assignment": "none: every policy is created unassigned",
    }
    if problems:
        return {**out, "status": "blocked", "blockers": problems, "plan": actions}
    if not confirm:
        differ = push.compare_with_intune(graph, actions, out_dir)
        stale = [n for n in differ if n not in set(replace or [])]
        warn = push.warnings(plan)
        if leftover:
            warn.append(f"{len(leftover)} policies in Intune come from an earlier run of this baseline but aren't "
                        "generated any more, so pushing won't update them and they keep applying old settings: "
                        + "; ".join(leftover) + ". Tell the person to delete or unassign them in Intune.")
        if stale:
            warn.append(f"{len(stale)} existing policies differ from this generated version and would be skipped: "
                        + "; ".join(stale) + ". Tell the person; replace them to update (replace=[names]).")
        return {
            **out, "status": "plan_only", "plan": actions,
            "warnings": warn,
            "next": PLAN_NEXT,
        }
    results = push.execute(graph, actions, out_dir)
    (out_dir / "push.json").write_text(json.dumps({
        "pushed_at": datetime.now(timezone.utc).isoformat(), "tenant": t.name, "results": results,
    }, indent=2), encoding="utf-8")
    failed = [r for r in results if r["result"] == "failed"]
    return {
        **out, "status": "done" if not failed else "done_with_errors",
        "results": [{k: v for k, v in r.items() if k != "file"} for r in results],
        "next": "Run check_tenant_coverage: the new policies should show as covered_unassigned. "
                "Assign them in Intune when you are ready, ideally to a pilot group first.",
    }


@mcp.tool(annotations=INTUNE_WRITE)
def push_compliance(
    baseline: Annotated[str, Field(description="Baseline key whose generated compliance to push.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    confirm: Annotated[
        bool, Field(description="False (default): only show the plan. True: create, after the person said yes."),
    ] = False,
    replace: Annotated[
        list[str] | None,
        Field(description="Names of existing compliance policies to overwrite (their discovery script too). "
              "Only when the person asked for that."),
    ] = None,
    only: Annotated[list[str] | None, Field(description="Push only these generated policy names.")] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Create the compliance policies generate_compliance wrote, unassigned: first each discovery
    script, then the policy that uses it. Call without confirm first and show the plan; call with
    confirm=true only after the person approves. Existing ones are skipped unless named in replace.
    Nothing is assigned or deleted."""
    plat = parse_platform(platform)
    ref, _ = _load(baseline, plat, os_version)
    out_dir = _gen_dir(tenant, ref, "compliance")
    try:
        plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise UserInputError("Nothing generated yet. Run generate_compliance first and review it.") from None
    if only:
        names = {p["name"] for p in plan["policies"]}
        unknown = [n for n in only if n not in names]
        if unknown:
            raise UserInputError(f"Not in the generated set: {', '.join(unknown)}")
        plan = {**plan, "policies": [p for p in plan["policies"] if p["name"] in only]}
    t = _tenants().get(tenant)
    problems = push.blockers(plan, t.name, t.permission_set)
    graph = _graph(tenant)
    policies, scripts = push.existing_compliance(graph, plat)
    actions = push.plan_compliance(plan, policies, scripts, replace)
    out: dict[str, Any] = {"baseline": ref.name, "platform": plat.display, "tenant": t.name,
                           "generated_at": plan.get("generated_at"),
                           "assignment": "none: every policy is created unassigned"}
    if problems:
        return {**out, "status": "blocked", "blockers": problems, "plan": actions}
    if not confirm:
        return {**out, "status": "plan_only", "plan": actions, "warnings": push.warnings(plan),
                "next": PLAN_NEXT}
    results = push.execute_compliance(graph, actions, out_dir)
    (out_dir / "push.json").write_text(json.dumps({"pushed_at": datetime.now(timezone.utc).isoformat(),
                                                   "tenant": t.name, "results": results}, indent=2),
                                       encoding="utf-8")
    failed = [r for r in results if r["result"] == "failed"]
    return {**out, "status": "done_with_errors" if failed else "done",
            "results": [{k: v for k, v in r.items() if k not in ("file", "script_body")} for r in results],
            "next": "Scripts run on the Mac's next check-in; results can take hours to show. Assign to a "
                    "pilot group first, ideally with a grace period, before Conditional Access relies on it."}


@mcp.tool(annotations=LOCAL_FILES_TENANT_READ)
def generate_remediation(
    baseline: Annotated[str, Field(description="Baseline key, mSCP or tailored, e.g. 'cis_lvl1'.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    prefix: Annotated[str | None, Field(description="Name prefix, e.g. 'CIS TST'. Saved per tenant, platform and baseline; ask the person when none is saved.")] = None,
    sections: Annotated[list[str] | None, Field(description="Only these mSCP sections.")] = None,
    exclude: Annotated[list[str] | None, Field(description="Rule IDs to leave out of the scripts.")] = None,
    include: Annotated[
        list[str] | None,
        Field(description="Profile-delivered rule IDs whose mSCP fix should run too (e.g. when the profile "
                          "doesn't take effect on some Macs)."),
    ] = None,
    include_per_user: Annotated[
        bool, Field(description="Also fix settings of the last logged-in user (default false).")
    ] = False,
    include_disruptive: Annotated[
        bool, Field(description="Also include fixes that install updates or may restart (default false).")
    ] = False,
    frequency: Annotated[
        Literal["once", "daily", "weekly"],
        Field(description="How often Intune runs each script; daily (default) undoes drift."),
    ] = "daily",
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Build remediation for a baseline as local files for review: per mSCP section one macOS shell
    script for the rules no policy can enforce (mSCP 'Script' rules). For each rule the script runs
    mSCP's check, runs mSCP's fix only when the check fails, then checks again and logs the result,
    so Macs that already pass are untouched. Rules that need Recovery, disruptive fixes and per-user
    fixes are left out unless asked. A few profile rules the profile doesn't fully enforce are
    included too (also_scripted says why, e.g. the screensaver unlock rule with Platform SSO).
    Nothing is sent to Intune.

    Present the result as a table per script (section, rules), then skipped with reasons. Remind
    the person these scripts change Macs: test one on a Mac first and assign to a pilot group."""
    from . import remediation

    plat = parse_platform(platform)
    if not plat.supports_custom_compliance:
        raise UserInputError("Remediation scripts are for macOS; iOS/iPadOS has no shell scripts.")
    ref, base = _load(baseline, plat, os_version)
    chosen, prefix_info = _prefix(tenant, plat, ref, prefix, creating=True)
    result = remediation.select(base, plat, sections=sections, exclude=exclude, include=include,
                                include_per_user=include_per_user, include_disruptive=include_disruptive)
    if result["not_found"]:
        raise UserInputError(f"Not in {ref.name}: {', '.join(result['not_found'])}")
    out_dir = _gen_dir(tenant, ref, "remediation")
    scripts = remediation.write(
        result, out_dir, prefix=chosen, platform=plat, baseline_display=tailoring.display_name(ref),
        baseline_name=ref.name, os_version=ref.os_version, mscp_version=_source().mscp_version,
        frequency=frequency,
    )
    (out_dir / "plan.json").write_text(json.dumps({
        "baseline": ref.name, "platform": plat.display, "prefix": chosen,
        "tenant": _tenants().get(tenant).name, "generated_at": datetime.now(timezone.utc).isoformat(),
        "scripts": scripts, "skipped": result["skipped"],
    }, indent=2), encoding="utf-8")
    return {
        "baseline": ref.name, "platform": plat.display, **prefix_info, "output_folder": str(out_dir),
        "scripts": [{k: v for k, v in s.items() if k not in ("file",)} for s in scripts],
        "counts": {"scripts": len(scripts), "rules": sum(len(s["rules"]) for s in scripts),
                   "skipped": len(result["skipped"])},
        "skipped": result["skipped"],
        "notes": [
            "Files only: nothing was sent to Intune. These scripts change Macs when a check fails.",
            "Test one on a Mac first: sudo env -i /bin/bash <file>.sh prints a summary line; details in "
            f"{remediation.LOG_DIR}.",
            "Some fixes (launchd services) only take effect after a restart; the script reports those "
            "as still failing until then.",
        ],
    }


@mcp.tool(annotations=INTUNE_WRITE)
def push_remediation(
    baseline: Annotated[str, Field(description="Baseline key whose generated remediation to push.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    confirm: Annotated[
        bool, Field(description="False (default): only show the plan. True: create, after the person said yes."),
    ] = False,
    replace: Annotated[
        list[str] | None,
        Field(description="Names of existing shell scripts to overwrite. Only when the person asked for that."),
    ] = None,
    only: Annotated[list[str] | None, Field(description="Push only these generated script names.")] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Create the macOS shell scripts generate_remediation wrote in Intune, unassigned. Call without
    confirm first and show the plan; call with confirm=true only after the person approves. Existing
    scripts with the same name are skipped unless named in replace. Nothing is assigned or deleted."""
    plat = parse_platform(platform)
    ref, _ = _load(baseline, plat, os_version)
    out_dir = _gen_dir(tenant, ref, "remediation")
    try:
        plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise UserInputError("Nothing generated yet. Run generate_remediation first and review it.") from None
    if only:
        names = {s["name"] for s in plan["scripts"]}
        unknown = [n for n in only if n not in names]
        if unknown:
            raise UserInputError(f"Not in the generated set: {', '.join(unknown)}")
        plan = {**plan, "scripts": [s for s in plan["scripts"] if s["name"] in only]}
    t = _tenants().get(tenant)
    problems = push.blockers(plan, t.name, t.permission_set)  # scripts don't depend on the tenant
    graph = _graph(tenant)
    actions = push.plan_remediation(plan, push.existing_shell_scripts(graph), replace)
    out: dict[str, Any] = {"baseline": ref.name, "platform": plat.display, "tenant": t.name,
                           "generated_at": plan.get("generated_at"),
                           "assignment": "none: every script is created unassigned"}
    if problems:
        return {**out, "status": "blocked", "blockers": problems, "plan": actions}
    if not confirm:
        return {**out, "status": "plan_only", "plan": actions, "warnings": push.warnings(plan),
                "next": PLAN_NEXT}
    results = push.execute_remediation(graph, actions, out_dir)
    (out_dir / "push.json").write_text(json.dumps({"pushed_at": datetime.now(timezone.utc).isoformat(),
                                                   "tenant": t.name, "results": results}, indent=2),
                                       encoding="utf-8")
    failed = [r for r in results if r["result"] == "failed"]
    return {**out, "status": "done_with_errors" if failed else "done",
            "results": [{k: v for k, v in r.items() if k != "file"} for r in results],
            "next": "Assign to one test Mac first. Scripts run at the next check-in; the run status and "
                    "the log in /Library/Logs/apple-intune-baseline show what changed."}


@mcp.tool(annotations=LOCAL_FILES_TENANT_READ)
def device_results(
    baseline: Annotated[str, Field(description="Baseline key whose compliance and remediation to report on.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    device: Annotated[str | None, Field(description="Only Macs whose name contains this, or this serial.")] = None,
    export: Annotated[
        list[Literal["pdf", "csv", "html"]] | None,
        Field(description="Also write to the workspace: 'html' an interactive dashboard (search, filters, "
              "drill-down from charts), 'pdf' a report, 'csv' one row per Mac and check."),
    ] = None,
    prefix: Annotated[str | None, Field(description="Name prefix it was pushed with; defaults to the one saved for this tenant, platform and baseline.")] = None,
    max_devices: Annotated[int, Field(ge=1, le=500, description="At most this many Macs (default 50).")] = 50,
    os_version: OsVersionArg = None,
    include: Annotated[
        list[Literal["compliance", "profiles"]] | None,
        Field(description="'compliance': compliance policies and remediation scripts. 'profiles': how the "
              "baseline's configuration profiles landed, per setting (succeeded / not applicable / error). "
              "Default both."),
    ] = None,
) -> dict[str, Any]:
    """Read-only: per device, how this baseline's configuration profiles, compliance policies and
    remediation scripts are doing. Profiles: per Settings Catalog policy the settings that didn't
    succeed, with Intune's error code and, when a device requirement explains it (needs a newer OS,
    a supervised device), that requirement as 'expected'; per custom profile installed or not. For each Mac: state and last report per policy, the failing checks as mSCP rules with
    titles, the last remediation run with what it fixed, and a 'stale' flag when Intune's result is
    older than the last fix (Intune keeps it until the discovery script runs again). Optionally
    exports an interactive HTML dashboard, a PDF report and a CSV.

    Present the summary first, then a table per Mac (section, state, failing, last reported), then
    failing rules. Say clearly when a result is stale rather than calling the Mac non-compliant.
    For profiles, separate settings that failed as expected (device requirements) from unexplained
    ones."""
    from . import profile_status, report, results

    parts = set(include or ["compliance", "profiles"])

    plat = parse_platform(platform)
    ref, base = _load(baseline, plat, os_version)
    chosen, prefix_info = _prefix(tenant, plat, ref, prefix, creating=False)
    display = tailoring.display_name(ref)
    own_prefix = generate.policy_name(chosen, plat, display, ref.os_version, "", "")[:-3]
    titles = {r.rule_id: " ".join(str(r.title).split()) for p in base.profile for r in p.rules}
    t = _tenants().get(tenant)
    graph = _graph(tenant)
    data = results.gather(graph, plat, own_prefix, titles, device=device, max_devices=max_devices) \
        if "compliance" in parts else {"policies": [], "scripts": [], "devices": [], "summary": {},
                                       "generated_at": datetime.now(timezone.utc).isoformat()}
    profiles = None
    if "profiles" in parts:
        parts_found = []
        for variant in (False, True):  # both sets of this baseline: supervised and unsupervised
            try:
                plan = json.loads((_policies_dir(tenant, ref, variant) / "plan.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                plan = None
            got = profile_status.gather(graph, plat, _variant_prefix(chosen, plat, ref, variant), plan, device=device)
            if got["profiles"]:
                parts_found.append(("unsupervised" if variant else "supervised", plan, got))
        profiles = profile_status.merge(parts_found)
        if len(profiles["devices"]) > max_devices:
            profiles["not_shown"] = len(profiles["devices"]) - max_devices
            profiles["devices"] = profiles["devices"][:max_devices]
        if any(plan is None for _, plan, _ in parts_found):
            profiles["note"] = ("No generated plan for a set here, so device requirements can't explain its "
                                "settings that didn't succeed.")
    files: dict[str, str] = {}
    if export and data["policies"] + data["scripts"]:
        folder = _report_dir(tenant, ref)
        folder.mkdir(parents=True, exist_ok=True)
        stem = f"{ref.name}_compliance_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
        title = f"{display} {ref.os_version} – {plat.display} compliance report"
        if "pdf" in export:
            files["pdf"] = str(report.write_pdf(data, folder / f"{stem}.pdf", title=title, tenant=t.name,
                                                baseline=ref.name))
        if "csv" in export:
            files["csv"] = str(report.write_csv(data, folder / f"{stem}.csv"))
        if "html" in export:
            files["html"] = str(report.write_html(data, folder / f"{stem}.html", title=title, tenant=t.name,
                                                  baseline=ref.name))
    if not data["policies"] and not data["scripts"] and not (profiles and profiles["profiles"]):
        what = " or ".join(w for w, on in (("configuration profiles", profiles is not None),
                                         ("compliance policies or remediation scripts", "compliance" in parts)) if on)
        raise UserInputError(f"No {what} named '{own_prefix}…' in {t.name}. Push them first, or pass the "
                             "prefix they were pushed with.")
    compact = [
        {"device": d["device"], "serial": d["serial"], "user": d["user"], "os": d["os"],
         "compliance": d["compliance"], "last_sync": d["last_sync"],
         "policies": [{"section": r["section"], "state": r["state"], "checks": r["checks"],
                       "failing": [f["rule"] for f in r["failing"]], "last_reported": r["last_reported"],
                       **({"stale": r["stale"]} if r.get("stale") else {})} for r in d["policies"]],
         "remediation": [{"section": r["section"], "state": r["state"], "at": r["at"], "result": r["result"]}
                         for r in d["remediation"]]}
        for d in data["devices"]
    ]
    notes = []
    if "compliance" in parts:
        notes.append("Stale results: Company Portal > Check status on the Mac asks Intune to evaluate again.")
        if not data["policies"] and not data["scripts"]:
            notes.append("No compliance policies or remediation scripts of this baseline in the tenant yet.")
    if profiles is not None:
        notes.append("Profiles: 'expected' means a device requirement from Apple's schema explains the result "
                     "(e.g. needs a supervised Mac); the rest are worth a look. Exports cover compliance only.")
    return {
        "tenant": t.name, "baseline": ref.name, **prefix_info, "generated_at": data["generated_at"],
        **({"summary": data["summary"], "devices": compact} if "compliance" in parts else {}),
        **({"not_shown": data["not_shown"]} if data.get("not_shown") else {}),
        **({"profiles": profiles} if profiles is not None else {}),
        **({"files": files} if files else {}),
        "notes": notes,
    }


def _own_prefix(chosen: str, plat: Platform, ref) -> str:
    return generate.policy_name(chosen, plat, tailoring.display_name(ref), ref.os_version, "", "")[:-3]


@mcp.tool(annotations=LOCAL_FILES_TENANT_READ)
def generate_inventory(
    baseline: Annotated[str, Field(description="Baseline key, mSCP or tailored, e.g. 'cis_lvl1'.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    prefix: Annotated[str | None, Field(description="Name prefix, e.g. 'CIS TST'. Saved per tenant, platform and baseline; ask the person when none is saved.")] = None,
    sections: Annotated[list[str] | None, Field(description="Only these mSCP sections.")] = None,
    exclude: Annotated[list[str] | None, Field(description="Rule IDs to leave out.")] = None,
    include_per_user: Annotated[
        bool, Field(description="Also report settings read from the last logged-in user (default false).")
    ] = False,
    attribute_prefix: Annotated[
        str | None, Field(description="Start of the custom attribute names; defaults to the name prefix.")
    ] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Build inventory for a baseline as local files for review: per mSCP section one macOS custom
    attribute script that reports the raw value of every rule's mSCP check as one flat line
    (rule_id=value; rule_id=value; ...; collected=<time>; not JSON, which Intune rejects). No pass/fail and no changes to the Mac: data for
    a CMDB or reporting. Includes rules that profiles enforce. Also writes a field dictionary per
    section (title, expected value, delivery). Nothing is sent to Intune.

    Present a table per attribute (section, attribute name, rules)."""
    from . import inventory

    plat = parse_platform(platform)
    if not plat.supports_custom_compliance:
        raise UserInputError("Custom attributes are for macOS; iOS/iPadOS has no shell scripts.")
    ref, base = _load(baseline, plat, os_version)
    chosen, prefix_info = _prefix(tenant, plat, ref, prefix, creating=True)
    result = inventory.select(base, plat, sections=sections, exclude=exclude, include_per_user=include_per_user)
    if result["not_found"]:
        raise UserInputError(f"Not in {ref.name}: {', '.join(result['not_found'])}")
    out_dir = _gen_dir(tenant, ref, "inventory")
    scripts = inventory.write(
        result, out_dir, prefix=chosen, platform=plat, baseline_display=tailoring.display_name(ref),
        baseline_name=ref.name, os_version=ref.os_version, mscp_version=_source().mscp_version,
        parent_values=getattr(base, "parent_values", "") or "", attribute_prefix=attribute_prefix or chosen,
    )
    (out_dir / "plan.json").write_text(json.dumps({
        "baseline": ref.name, "platform": plat.display, "prefix": chosen,
        "tenant": _tenants().get(tenant).name, "generated_at": datetime.now(timezone.utc).isoformat(),
        "scripts": scripts, "skipped": result["skipped"],
    }, indent=2), encoding="utf-8")
    return {
        "baseline": ref.name, **prefix_info, "output_folder": str(out_dir),
        "attributes": [{"name": s["name"], "attribute": s["attribute"], "section": s["section"],
                        "rules": len(s["rules"])} for s in scripts],
        "counts": {"attributes": len(scripts), "rules": sum(len(s["rules"]) for s in scripts),
                   "skipped": len(result["skipped"])},
        "skipped": result["skipped"],
        "notes": [
            "Files only: nothing was sent to Intune. Inventory reads; it never changes the Mac.",
            "Test on a Mac: sudo env -i /bin/bash <file>.sh prints one line: rule=value; ...; collected=<time>.",
            "Intune runs custom attributes every 8 hours; each value is at most 20 KB.",
        ],
    }


@mcp.tool(annotations=INTUNE_WRITE)
def push_inventory(
    baseline: Annotated[str, Field(description="Baseline key whose generated inventory to push.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    confirm: Annotated[
        bool, Field(description="False (default): only show the plan. True: create, after the person said yes."),
    ] = False,
    replace: Annotated[
        list[str] | None,
        Field(description="Names of existing custom attributes to overwrite. Only when the person asked."),
    ] = None,
    only: Annotated[list[str] | None, Field(description="Push only these generated names.")] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Create the macOS custom attributes generate_inventory wrote in Intune, unassigned. Call without
    confirm first and show the plan; call with confirm=true only after the person approves. Existing
    ones with the same name are skipped unless named in replace. Nothing is assigned or deleted."""
    plat = parse_platform(platform)
    ref, _ = _load(baseline, plat, os_version)
    out_dir = _gen_dir(tenant, ref, "inventory")
    try:
        plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise UserInputError("Nothing generated yet. Run generate_inventory first and review it.") from None
    if only:
        names = {s["name"] for s in plan["scripts"]}
        unknown = [n for n in only if n not in names]
        if unknown:
            raise UserInputError(f"Not in the generated set: {', '.join(unknown)}")
        plan = {**plan, "scripts": [s for s in plan["scripts"] if s["name"] in only]}
    t = _tenants().get(tenant)
    problems = push.blockers(plan, t.name, t.permission_set)
    graph = _graph(tenant)
    actions = push.plan_remediation(plan, push.existing_shell_scripts(graph, push.CUSTOM_ATTRIBUTES), replace)
    out: dict[str, Any] = {"baseline": ref.name, "platform": plat.display, "tenant": t.name,
                           "generated_at": plan.get("generated_at"),
                           "assignment": "none: every custom attribute is created unassigned"}
    if problems:
        return {**out, "status": "blocked", "blockers": problems, "plan": actions}
    if not confirm:
        return {**out, "status": "plan_only", "plan": actions, "warnings": push.warnings(plan), "next": PLAN_NEXT}
    results = push.execute_remediation(graph, actions, out_dir, push.CUSTOM_ATTRIBUTES)
    (out_dir / "push.json").write_text(json.dumps({"pushed_at": datetime.now(timezone.utc).isoformat(),
                                                   "tenant": t.name, "results": results}, indent=2),
                                       encoding="utf-8")
    failed = [r for r in results if r["result"] == "failed"]
    return {**out, "status": "done_with_errors" if failed else "done",
            "results": [{k: v for k, v in r.items() if k not in ("file", "frequency")} for r in results],
            "next": "Assign to a test Mac. Values arrive within 8 hours; read them with inventory_results."}


@mcp.tool(annotations=LOCAL_FILES_TENANT_READ)
def inventory_results(
    baseline: Annotated[str, Field(description="Baseline key whose inventory to read.")],
    platform: PlatformArg = "macos",
    tenant: TenantArg = None,
    device: Annotated[str | None, Field(description="Only Macs whose name contains this, or this serial.")] = None,
    rules: Annotated[
        list[str] | None, Field(description="Show every value for these rule IDs (default: only what differs or is empty).")
    ] = None,
    export: Annotated[
        list[Literal["csv", "json", "html"]] | None,
        Field(description="Also write 'csv' (one row per Mac and rule), 'json' (per Mac, with the field dictionary) "
              "and/or 'html' (interactive report: values against mSCP's expected values, search and filters)."),
    ] = None,
    prefix: Annotated[str | None, Field(description="Name prefix it was pushed with; defaults to the one saved for this tenant, platform and baseline.")] = None,
    max_devices: Annotated[int, Field(ge=1, le=1000, description="At most this many Macs (default 100).")] = 100,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Read-only: the values this baseline's custom attributes reported, per Mac and rule (raw mSCP
    check output), compared with what mSCP's check prints when the rule is met: matches, differs,
    no value (the check printed nothing, often a setting that isn't managed) or not applicable.
    Inventory doesn't judge compliance; the comparison is for reading the values. Base64 values
    (login window text) are decoded in 'readable'. Optionally exports CSV, JSON and an HTML report.

    Sections marked possibly_outdated reported before the baseline's profiles last changed (or
    not for a day): say so next to their 'differs'.
    Present per Mac the counts, then the rules that differ and those with no value (value against
    expected). Don't list every matching value unless asked."""
    from . import inventory, report

    plat = parse_platform(platform)
    ref, base = _load(baseline, plat, os_version)
    chosen, prefix_info = _prefix(tenant, plat, ref, prefix, creating=False)
    own = _own_prefix(chosen, plat, ref)
    parent = getattr(base, "parent_values", "") or ""
    meta = {r.rule_id: inventory.field_info(r, p.section, parent) for p in base.profile for r in p.rules}
    graph = _graph(tenant)
    t = _tenants().get(tenant)
    attrs = [a for a in graph.get_all(push.CUSTOM_ATTRIBUTES, {"$select": "id,displayName,customAttributeName"})
             if str(a.get("displayName", "")).startswith(own) and a["displayName"].endswith(" - Inventory")]
    if not attrs:
        raise UserInputError(f"No custom attributes named '{own}… - Inventory' in {t.name}. Push them first.")
    from . import profile_status
    changed = sorted((p["modified"], p["name"]) for v in (False, True)
                     for p in profile_status.own_profiles(graph, plat, _variant_prefix(chosen, plat, ref, v))
                     if p.get("modified"))
    last_change = changed[-1] if changed else None
    now = datetime.now(timezone.utc)
    info_cache: dict[str, dict] = {}
    per_device: dict[str, dict] = {}
    for a in attrs:
        section = a["displayName"][len(own):].rsplit(" - ", 1)[0]
        # Intune stores customAttributeName as null; use the name this tool gave it
        attr_name = a.get("customAttributeName") or inventory.attribute_name(chosen, section)
        for run in graph.get_all(f"{push.CUSTOM_ATTRIBUTES}/{a['id']}/deviceRunStates"):
            did = str(run.get("id", "")).split(":")[-1]
            if did not in info_cache:
                try:
                    info_cache[did] = graph.get(f"/deviceManagement/managedDevices/{did}",
                                                {"$select": "deviceName,serialNumber,userPrincipalName,osVersion"})
                except Exception:  # retired or no access: keep the ID
                    info_cache[did] = {"deviceName": did}
            info = info_cache[did]
            if device and device.lower() not in str(info.get("deviceName", "")).lower() \
                    and device.lower() != str(info.get("serialNumber", "")).lower():
                continue
            d = per_device.setdefault(did, {"device": info.get("deviceName"), "serial": info.get("serialNumber"),
                                            "user": info.get("userPrincipalName"), "os": info.get("osVersion"),
                                            "sections": {}})
            values = inventory.parse_value(run.get("resultMessage"))
            outdated = inventory.possibly_outdated(run.get("lastStateUpdateDateTime"), last_change, now)
            d["sections"][section] = {
                "attribute": attr_name, "state": run.get("runState"),
                "reported_at": run.get("lastStateUpdateDateTime"),
                **({"possibly_outdated": outdated} if outdated else {}),
                "collected": (values or {}).pop("_collected", None),
                **({"values": values} if values is not None else
                   {"error": run.get("resultMessage") or run.get("errorDescription")
                    or f"run {run.get('runState') or 'failed'}, no value (error {run.get('errorCode')})"}),
            }
    devices = sorted(per_device.values(), key=lambda d: str(d["device"]).lower())
    not_shown = max(0, len(devices) - max_devices)
    devices = devices[:max_devices]
    rows = []
    for d in devices:
        for sec, v in d["sections"].items():
            for rid, val in (v.get("values") or {}).items():
                m = meta.get(rid)
                rows.append({"device": d["device"], "serial": d["serial"], "user": d["user"], "os": d["os"],
                             "section": (m or {}).get("section") or sec, "attribute": v["attribute"], "rule": rid,
                             "title": (m or {}).get("title", ""), "value": val,
                             "readable": inventory.readable(val, m),
                             "mscp_expected": (m or {}).get("expected_readable", (m or {}).get("expected", "")),
                             "compared": inventory.compare(val, m), "delivery": (m or {}).get("delivery", ""),
                             "collected": v.get("collected"), "reported_at": v.get("reported_at")})
    reported_rules = {r["rule"] for r in rows}
    not_collected = sorted(set(meta) - reported_rules) if rows else []
    files: dict[str, str] = {}
    if export:
        import csv
        folder = _report_dir(tenant, ref)
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc)
        stem = f"{ref.name}_inventory_{stamp.strftime('%Y%m%d-%H%M')}"
        if "csv" in export:
            path = folder / f"{stem}.csv"
            with path.open("w", newline="", encoding="utf-8-sig") as f:
                w = csv.DictWriter(f, fieldnames=["device", "serial", "user", "os", "section", "attribute", "rule",
                                                  "title", "value", "readable", "mscp_expected", "compared",
                                                  "delivery", "collected", "reported_at"])
                w.writeheader()
                w.writerows(rows)
            files["csv"] = str(path)
        if "json" in export:
            path = folder / f"{stem}.json"
            path.write_text(json.dumps({"tenant": t.name, "baseline": ref.name, "generated_at": stamp.isoformat(),
                                        "fields": meta, "devices": devices}, indent=2, ensure_ascii=False,
                                       default=str), encoding="utf-8")
            files["json"] = str(path)
        if "html" in export:
            path = folder / f"{stem}.html"
            report.write_inventory_html(
                {"generated_at": stamp.isoformat(), "rows": rows, "not_collected": not_collected,
                 "devices": [{k: d[k] for k in ("device", "serial", "user", "os")} | {
                     "sections": {sec: {k: v for k, v in s.items() if k != "values"}
                                  for sec, s in d["sections"].items()}} for d in devices],
                 "attributes": [a["displayName"] for a in attrs]},
                path, title=f"{tailoring.display_name(ref)} {ref.os_version} – {plat.display} inventory",
                tenant=t.name, baseline=ref.name)
            files["html"] = str(path)
    wanted = set(rules or [])
    summary_devices = []
    for d in devices:
        mine = [r for r in rows if r["device"] == d["device"] and r["serial"] == d["serial"]]
        counts: dict[str, int] = {}
        for r in mine:
            counts[r["compared"]] = counts.get(r["compared"], 0) + 1
        entry: dict[str, Any] = {
            **{k: d[k] for k in ("device", "serial", "user", "os")}, "counts": counts,
            "collected": sorted({s.get("collected") for s in d["sections"].values() if s.get("collected")}),
            "differs": [{"rule": r["rule"], "value": r["readable"], "expected": r["mscp_expected"]}
                        for r in mine if r["compared"] == "differs"],
            **({"possibly_outdated": {sec: s["possibly_outdated"] for sec, s in d["sections"].items()
                                      if s.get("possibly_outdated")}}
               if any(s.get("possibly_outdated") for s in d["sections"].values()) else {}),
            "no_value": [r["rule"] for r in mine if r["compared"] == "no value"],
        }
        errors = {sec: s["error"] for sec, s in d["sections"].items() if "error" in s}
        if errors:
            entry["errors"] = errors
        if wanted:
            entry["values"] = [{k: r[k] for k in ("rule", "readable", "mscp_expected", "compared")}
                               for r in mine if r["rule"] in wanted]
        summary_devices.append(entry)
    return {"tenant": t.name, "baseline": ref.name, **prefix_info,
            "attributes": [a["displayName"] for a in attrs],
            "devices": summary_devices, "rows": len(rows),
            **({"not_collected": not_collected} if not_collected else {}),
            **({"not_shown": not_shown} if not_shown else {}),
            **({"files": files} if files else {}),
            "notes": ["Values are raw mSCP check output, compared with what mSCP's check prints when the rule is "
                      "met. 'no value': the check printed nothing, usually because the setting isn't managed or "
                      "the check reads a source (e.g. a DDM state file) that has no entry for it."]
            + (["possibly_outdated: these values were reported before this baseline's profiles last changed, or "
                "not for a day (by Intune's times, not the Mac's clock), so a 'differs' there may already be "
                "fixed. Custom attributes run on Intune's schedule; wait for the next report before judging."]
               if any(d.get("possibly_outdated") for d in summary_devices) else [])}


def self_test(
    platform: PlatformArg = "macos",
    os_version: Annotated[str, Field(description="'27.0' or '26.0'.")] = "27.0",
    round_trip: Annotated[
        bool, Field(description="Also create every all_rules object in the tenant under the prefix "
                                "'AIB-SELFTEST', unassigned, read it back, compare and delete it.")
    ] = False,
    confirm: Annotated[bool, Field(description="Required with round_trip or cleanup_only: the person agreed.")] = False,
    cleanup_only: Annotated[
        bool, Field(description="Only delete objects named 'AIB-SELFTEST - ...' left in the tenant (needs confirm).")
    ] = False,
    baselines: Annotated[list[str] | None, Field(description="Only these baseline keys (default: all).")] = None,
    tenant: TenantArg = None,
) -> dict[str, Any]:
    """Developer self-test: generate policies, compliance, remediation and inventory for every mSCP
    baseline of one platform and OS version (26.0 or 27.0) and check the output: profile and
    Managed Client payload shape, keys in two profiles, rules generated nowhere or with a false
    reason, catalog settings from the wrong payload domain or that didn't fit, script syntax,
    compliance rules vs script. Reads setting definitions from the tenant. With round_trip (and
    confirm), all_rules is created in the tenant unassigned as 'AIB-SELFTEST - ...', read back,
    compared and deleted; only objects with that prefix are ever deleted. Writes a JSON and
    Markdown report. Present the counts per check and the errors."""
    from . import selftest

    plat = parse_platform(platform)
    ver = f"{float(os_version):.1f}"
    if ver not in selftest.VERSIONS[plat]:
        raise UserInputError(f"The self-test covers {', '.join(selftest.VERSIONS[plat])} for {plat.display}.")
    if cleanup_only:
        if not confirm:
            raise UserInputError("cleanup_only deletes 'AIB-SELFTEST' objects: ask the person, then confirm=true.")
        graph = _graph(tenant)
        report = selftest.Report()
        found = selftest.leftovers(graph)
        deleted = selftest.delete(graph, found, report, "cleanup")
        return {"found": [n for _, _, n in found], "deleted": deleted,
                "errors": [f.detail for f in report.findings if f.severity == "error"]}
    if round_trip and not confirm:
        raise UserInputError("round_trip creates and deletes 'AIB-SELFTEST' objects in the tenant: ask the person, "
                             "then call again with confirm=true.")
    src = _source()
    t = _tenants().get(tenant)
    graph = _graph(tenant)
    work = _workspace().state_dir / "selftest" / f"{plat.value}_{ver}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    report = selftest.Report()
    defs = SettingDefinitions(graph, _workspace().state_dir / "settings_catalog_definitions.json")
    try:
        selftest.offline(src, defs, plat, ver, work, report, baselines)
        if round_trip:
            selftest.round_trip(src, graph, defs, plat, ver, work, report)
    finally:
        defs.save()
    folder = layout.tenant_dir(_workspace().state_dir, t.name) / "reports" / "selftest"
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"selftest_{plat.value}_{ver}_{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    (folder / f"{stem}.json").write_text(json.dumps(report.as_dict(), indent=2, default=str), encoding="utf-8")
    selftest.write_markdown(report, folder / f"{stem}.md", f"Self-test {plat.display} {ver} ({t.name})")
    findings = sorted(report.findings, key=lambda f: (f.severity != "error", f.check, f.baseline))
    return {**report.summary(), "platform": plat.display, "os_version": ver, "tenant": t.name,
            "findings": [vars(f) for f in findings[:80]],
            **({"not_shown": len(findings) - 80} if len(findings) > 80 else {}),
            "files": {"json": str(folder / f"{stem}.json"), "markdown": str(folder / f"{stem}.md")}}


# Developer tool: not part of the released tool list. Set APPLE_INTUNE_BASELINE_DEV=1 in the server's
# environment to get it, or run it without Claude: python -m apple_intune_baseline.selftest --help
if os.environ.get("APPLE_INTUNE_BASELINE_DEV") == "1":
    mcp.tool(annotations=INTUNE_WRITE)(self_test)


@mcp.tool(annotations=READ_ONLY)
def list_baselines(platform: PlatformArg = "macos", os_version: OsVersionArg = None) -> dict[str, Any]:
    """List the mSCP baselines (CIS, NIST 800-53, STIG, CMMC…) for a platform and OS version
    (default: the newest). Older versions mSCP supports (e.g. macOS/iOS 26) are built on first use
    with mSCP's own generator and can include benchmarks the newest doesn't have yet.

    Includes tailored baselines saved in the workspace, marked source='workspace'.
    """
    plat = parse_platform(platform)
    src = _source()
    ver = os_version or src.latest_os_version(plat)
    refs = [r for r in src.list_baselines(plat, ver) if r.os_version == f"{float(ver):.1f}"]
    return {
        "platform": plat.display,
        "os_version": f"{float(ver):.1f}",
        "baselines": [
            {"key": r.key, "name": r.name, "os_version": r.os_version, "source": r.source}
            for r in refs
            if r.key != "all_rules"
        ],
        "os_versions": src.supported_versions(plat),
        "note": "all_rules (every rule mSCP has) is also available as a baseline key. Other OS versions: "
                "pass os_version, e.g. '26.0'; every tool takes os_version too.",
    }


@mcp.tool(annotations=READ_ONLY)
def list_rules(
    platform: PlatformArg = "macos",
    baseline: Annotated[
        str | None, Field(description="Limit to a baseline, e.g. 'cis_lvl1'. Omit for every rule.")
    ] = None,
    section: Annotated[
        str | None, Field(description="mSCP section, e.g. 'Auditing', 'System Settings'.")
    ] = None,
    delivery: Annotated[
        str | None,
        Field(description="Filter: ddm, profile, script, manual or not_actionable."),
    ] = None,
    verification: Annotated[
        str | None,
        Field(
            description="Filter: builtin_compliance, enforced_not_verified, "
            "custom_compliance_candidate, unverifiable or none."
        ),
    ] = None,
    impact: Annotated[
        str | None,
        Field(description="Filter: breaks_workflows, user_visible or apple_intelligence."),
    ] = None,
    search: Annotated[str | None, Field(description="Case-insensitive match on ID or title.")] = None,
    os_version: OsVersionArg = None,
    limit: Annotated[int, Field(ge=1, le=500)] = 150,
) -> dict[str, Any]:
    """List mSCP rules with how each is delivered, verified and what users will notice."""
    plat = parse_platform(platform)
    ref, base = _load(baseline or "all_rules", plat, os_version)
    needle = (search or "").lower()
    rows = []
    for prof in base.profile:
        if section and prof.section.lower() != section.lower():
            continue
        for rule in prof.rules:
            if delivery and classify.delivery(rule) != delivery:
                continue
            if verification and classify.verification(rule, plat)["status"] != verification:
                continue
            if impact and impact not in classify.impact_tags(rule):
                continue
            if needle and needle not in rule.rule_id.lower() and needle not in rule.title.lower():
                continue
            rows.append(_summary(rule, plat, base.parent_values))
    return {
        "platform": plat.display,
        "baseline": ref.name,
        "total": len(rows),
        "truncated": len(rows) > limit,
        "rules": rows[:limit],
    }


@mcp.tool(annotations=READ_ONLY)
def explain_rule(
    rule_id: Annotated[str, Field(description="mSCP rule ID, e.g. 'os_airdrop_disable'.")],
    platform: PlatformArg = "macos",
    baseline: Annotated[
        str | None,
        Field(description="Baseline whose organization-defined values to show, e.g. 'cis_lvl1'."),
    ] = None,
    os_version: OsVersionArg = None,
) -> dict[str, Any]:
    """Everything about one rule: what it checks, how it is enforced, its value, user impact
    and framework references. Explain it in plain language for the person."""
    plat = parse_platform(platform)
    ref, base = _load(baseline or "all_rules", plat, os_version)
    rule = next((r for p in base.profile for r in p.rules if r.rule_id == rule_id), None)
    if rule is None:
        library = _source().rule_library(plat, os_version)
        rule = library.get(rule_id)
        if rule is None:
            close = [r for r in library if rule_id.lower() in r][:10]
            raise UserInputError(f"Unknown {plat.display} rule '{rule_id}'. Similar: {close}")
        in_baseline = False
    else:
        in_baseline = True

    detail = _summary(rule, plat, base.parent_values)
    detail.update(
        {
            "in_baseline": in_baseline if baseline else None,
            "baseline": ref.name,
            "mechanism": rule.mechanism,
            "verification_detail": classify.verification(rule, plat),
            "discussion": (rule.discussion or "").strip(),
            "check": rule.check,
            "expected_result": rule.result_value,
            "expected_exit_code": rule.result_exit_code,
            "fix": (rule.fix or "").strip() or None,
            "payloads": classify.payloads(rule) or None,
            "odv_options": {k: v for k, v in (rule.odv or {}).items() if k != "hint"} or None,
            "odv_hint": (rule.odv or {}).get("hint"),
            "references": classify.references(rule),
        }
    )
    return {k: v for k, v in detail.items() if v is not None}


@mcp.tool(annotations=READ_ONLY)
def baseline_overview(
    baseline: Annotated[str, Field(description="Baseline key, e.g. 'cis_lvl1' or '800-53r5_moderate'.")],
    platform: PlatformArg = "macos",
    os_version: OsVersionArg = None,
    include_rules: Annotated[
        bool,
        Field(
            description="Also list every rule ID per delivery and verification group. "
            "Large; prefer list_rules with a delivery or verification filter."
        ),
    ] = False,
) -> dict[str, Any]:
    """The big picture of a baseline: how rules are delivered, what verifies them, what users
    will notice, per section. Present it as tables. To see the rules in one group, call
    list_rules with baseline plus delivery, verification or impact; explain_rule for one rule."""
    plat = parse_platform(platform)
    ref, base = _load(baseline, plat, os_version)
    rules = [r for p in base.profile for r in p.rules]

    by_delivery: dict[str, list[str]] = defaultdict(list)
    by_verification: dict[str, list[str]] = defaultdict(list)
    by_impact: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        by_delivery[classify.delivery(rule)].append(rule.rule_id)
        by_verification[classify.verification(rule, plat)["status"]].append(rule.rule_id)
        for tag in classify.impact_tags(rule):
            by_impact[tag].append(rule.rule_id)

    sections = [
        {
            "section": p.section,
            "rules": len(p.rules),
            "delivery": dict(Counter(classify.delivery(r) for r in p.rules)),
        }
        for p in base.profile
    ]

    return {
        "baseline": ref.name,
        "title": base.title,
        "platform": plat.display,
        "source": ref.source,
        "mscp_version": _source().mscp_version,
        "total_rules": len(rules),
        "delivery": {
            k: {"label": classify.DELIVERY_LABELS[k], "count": len(v)}
            | ({"rules": v} if include_rules else {})
            for k, v in by_delivery.items()
        },
        "verification": {
            k: {"count": len(v)} | ({"rules": v} if include_rules else {})
            for k, v in by_verification.items()
        },
        # Short lists, and the answer to "what will users notice?", so always included.
        "impact": {k: {"count": len(v), "rules": v} for k, v in by_impact.items()},
        "sections": sections,
        "tenant_coverage": "not_checked (arrives in phase 2)",
        "notes": [
            "Impact tags come from a curated map in the MCP, not from mSCP; treat them as hints.",
            "custom_compliance_candidate = script-only rules nothing else verifies; "
            "the compliance selection step will propose these by default.",
        ]
        + (
            ["iOS/iPadOS has no custom compliance; rules without a built-in toggle are "
             "enforced but not verified."]
            if not plat.supports_custom_compliance
            else []
        ),
    }


# --------------------------------------------------------------- resources


@mcp.resource("mscp://baseline/{platform}/{name}")
def baseline_resource(platform: str, name: str) -> dict[str, Any]:
    """A baseline's rules grouped by section."""
    plat = parse_platform(platform)
    ref, base = _load(name, plat, None)
    return {
        "baseline": ref.name,
        "title": base.title,
        "sections": {p.section: [r.rule_id for r in p.rules] for p in base.profile},
    }


@mcp.resource("mscp://rule/{platform}/{rule_id}")
def rule_resource(platform: str, rule_id: str) -> dict[str, Any]:
    """One rule, as explain_rule returns it with mSCP's recommended values."""
    return explain_rule(rule_id, platform)


# ----------------------------------------------------------------- prompts


@mcp.prompt()
def review_baseline(baseline: str = "cis_lvl1", platform: str = "macos") -> str:
    """Walk through a baseline before a pilot: what it delivers and what users will notice."""
    return (
        f"Use baseline_overview for the {platform} baseline '{baseline}'. Summarize, as short "
        "tables: rules per delivery type, what verifies them, and the rules tagged "
        "breaks_workflows, user_visible and apple_intelligence. Then list the rules I most "
        "likely want to discuss before a pilot, and offer explain_rule on any of them."
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
