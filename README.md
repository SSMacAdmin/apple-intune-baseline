# apple-intune-baseline

An MCP server that turns [mSCP](https://github.com/usnistgov/macos_security) (the macOS Security Compliance Project) baselines into Microsoft Intune configuration, for **macOS** and **iOS/iPadOS**. Ask your AI assistant for "CIS Level 1 for macOS 27" and get the Intune policies, compliance checks, remediation scripts and inventory for it, reviewed as local files before anything reaches your tenant.

It stays close to mSCP: rules, baselines, sections and organization-defined values come from mSCP's own Python code, pinned to an mSCP release. The server runs locally on your Mac and needs no other MCP server.

## What you get

A baseline has four parts, each generated as local files and pushed separately:

| Part | What it is |
| --- | --- |
| **Profiles** | One Settings Catalog policy per mSCP section (DDM included) and, only where the catalog can't express a rule, a custom profile |
| **Compliance** | One compliance policy per section, checking every rule with mSCP's own checks (macOS); built-in compliance settings on iOS/iPadOS |
| **Remediation** (macOS) | Shell scripts for the rules no policy can enforce: mSCP's check, mSCP's fix only when it fails, then the check again |
| **Inventory** (macOS) | Custom attributes reporting each rule's raw value per Mac, for a CMDB or reporting |

Before generating, it checks what your tenant already configures and verifies, so nothing is duplicated. Afterwards it reads per-device results back into an interactive dashboard, PDF and CSV.

Baselines: everything mSCP ships, e.g. CIS Level 1 and 2, NIST 800-53 (low, moderate, high), NIST 800-171, CMMC, DISA STIG, for macOS 27.0 and 26.0 and iOS/iPadOS 27.0 and 26.0. You can tailor a copy: exclude rules with a reason, add rules, change organization-defined values.

## Safety

- **Generating only writes local files.** Review them before you push.
- **Pushing shows a plan first** (create, skip because the name exists, replace) and creates only after you confirm.
- **Everything is created unassigned.** Nothing reaches a device until you assign it in Intune, ideally to a pilot group first.
- **Nothing is ever deleted.** Existing policies are only overwritten when you name them in `replace`.
- **Read-only by default.** The app registration it creates for you can only read your tenant unless you choose the `full` permission set.
- Settings that change how people sign in (password policy, login window) and payloads that need configuration before pushing are flagged as heads-ups. Test on a device you can recover.

## Install

Requires macOS (sign-in tokens live in the Keychain) and [uv](https://docs.astral.sh/uv/) (`brew install uv`). uv fetches Python 3.12+, this server and the pinned mSCP release; the first start takes about a minute while mSCP is built, later starts come from uv's cache.

**Claude Code:**

```sh
claude mcp add apple-intune-baseline -- uvx --from git+https://github.com/SSMacAdmin/apple-intune-baseline@v0.1.0 apple-intune-baseline
```

**Claude Desktop:** add to `~/Library/Application Support/Claude/claude_desktop_config.json`, using the full path from `which uvx` (Claude Desktop doesn't see your shell's `PATH`), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "apple-intune-baseline": {
      "command": "/opt/homebrew/bin/uvx",
      "args": ["--from", "git+https://github.com/SSMacAdmin/apple-intune-baseline@v0.1.0", "apple-intune-baseline"]
    }
  }
}
```

Other MCP clients: run the same `uvx` command as a stdio server.

**Updating:** change `@v0.1.0` to the new release tag and restart the client. Your workspace (`~/.apple-intune-baseline`: tenants, prefixes, generated files, reports) stays where it is.

## Quick start

Ask your assistant, in your own words:

1. "Which mSCP baselines are there for macOS 27?" and "Give me an overview of CIS Level 1": what each baseline delivers, and the rules users will notice.
2. "Connect to my Intune tenant": creates a read-only app registration once (you approve in the browser), then signs in.
3. "What does my tenant already cover of CIS Level 1?"
4. "Generate CIS Level 1 for macOS 27": profiles first, then it offers compliance, remediation and inventory.
5. "Push the policies": shows the plan, creates them unassigned after you say yes. Pushing needs the `full` permission set.
6. After assigning to a pilot group: "How are my Macs doing on CIS Level 1?"

## Tools

Every baseline tool takes `platform`: `macos` (default) or `ios` (iPhone and iPad), and `os_version` (default: the newest).

### Explore

| Tool | What it does |
| --- | --- |
| `workspace_status` | Pinned mSCP release, workspace location, sign-in state |
| `list_baselines` | CIS, NIST 800-53, STIG, CMMC… per platform, plus tailored ones |
| `list_rules` | Filter by baseline, section, delivery, verification, impact tag or text |
| `explain_rule` | What a rule checks, how it's enforced, its value, user impact, references |
| `baseline_overview` | Per baseline: counts per delivery and verification bucket, impact lists, per section. `include_rules=true` adds every rule ID |
| `name_prefixes` | List the saved name prefixes (per tenant, platform and baseline), or save/remove one |

### Tenants and sign-in

| Tool | What it does |
| --- | --- |
| `setup_app_registration` | One-time per tenant: creates this server's own app registration |
| `add_tenant` | Alternative: register an existing app registration's IDs and its `permission_set` (`readOnly` default, `full` to push) |
| `use_tenant` / `list_tenants` | Switch the active tenant, see who is signed in |
| `sign_in` / `sign_out` | Browser sign-in, non-blocking (returns `pending` while you sign in); tokens in the macOS Keychain |
| `check_connection` | Read-only: counts the tenant's macOS and iOS Settings Catalog policies |
| `check_tenant_coverage` | Read-only: which baseline rules the tenant already enforces (configuration policies) and verifies (compliance policies), where, with what value, and whether those policies are assigned |

### Tailor, generate and push

| Tool | What it does |
| --- | --- |
| `tailor_baseline` | Create or change a tailored copy of an mSCP baseline: exclude rules (with a reason), add rules, change organization-defined values. Saved in mSCP's format in the workspace |
| `generate_policies` | Writes the Intune policies for a baseline as local files for review: per mSCP section one Settings Catalog policy (DDM included) and, only where needed, one custom profile. Skips what the tenant already has. Sends nothing to Intune |
| `push_policies` | Creates the generated policies in Intune, unassigned. First call shows the plan (create / skip because the name exists / replace); a second call with `confirm=true` creates. Never assigns or deletes |
| `generate_compliance` | Selective compliance as local files: per mSCP section one compliance policy with a discovery script (mSCP's own checks, read-only) and rules JSON. On macOS every check is in the script by default; `include_builtin=true` uses Intune's built-in settings where they exist |
| `push_compliance` | Uploads each discovery script, then creates the compliance policy that uses it, unassigned. Plan first, `confirm=true` to create, `replace` to overwrite |
| `generate_remediation` | macOS shell scripts as local files, one per mSCP section, for the rules no policy can enforce: mSCP's check, then mSCP's fix only when the check fails, then the check again |
| `push_remediation` | Creates the shell scripts in Intune, unassigned. Plan first, `confirm=true` to create, `replace` to overwrite |
| `generate_inventory` | macOS custom attributes as local files, one per mSCP section: the raw value of every rule's mSCP check as one flat `rule=value; …` line, for a CMDB. No pass/fail, no changes. Plus a field dictionary per section |
| `push_inventory` | Creates the custom attributes in Intune, unassigned. Plan first, `confirm=true` to create, `replace` to overwrite |

### Results

| Tool | What it does |
| --- | --- |
| `device_results` | Read-only: per Mac, each of this baseline's compliance policies (state, last report, failing checks as mSCP rules) and the last remediation runs, with stale results flagged. `export=["html","pdf","csv"]` writes an interactive dashboard, a PDF report and a CSV |
| `inventory_results` | Read-only: per Mac, what the custom attributes reported compared with mSCP (matches, differs, no value), listing what differs and what's empty. `export=["csv","json","html"]` for a CMDB or an interactive report |

Resources: `mscp://baseline/{platform}/{name}` and `mscp://rule/{platform}/{rule_id}`. Prompt: `review_baseline`.

How each part behaves in detail (naming, device requirements, supervised and unsupervised sets, prefixes, the scripts, the workspace layout): [docs/reference.md](docs/reference.md).

## Permissions

`setup_app_registration` signs in once with Microsoft Graph PowerShell's public client (as `Connect-MgGraph` does), then creates a single-tenant public client app (`http://localhost` redirect, no secret) with delegated permissions, its Enterprise App, optional assignment to only you, and admin consent. The setup tokens are kept in memory only and dropped afterwards. Re-running updates the app with the same name.

| Permission set | Delegated Graph permissions |
| --- | --- |
| `readOnly` (default) | `User.Read`, `DeviceManagementConfiguration.Read.All`, `GroupMember.Read.All`, `DeviceManagementScripts.Read.All`, `DeviceManagementManagedDevices.Read.All` |
| `full` (pushing) | `User.Read`, `DeviceManagementConfiguration.ReadWrite.All`, `GroupMember.Read.All`, `DeviceManagementScripts.ReadWrite.All`, `DeviceManagementManagedDevices.Read.All` |

`tenants.json` in the workspace holds only the tenant ID, client ID, default domain and permission set. No secrets are stored.

## Known limitations

- **A tenant is needed to generate.** Settings Catalog policies are built from Microsoft's setting definitions, which are read through a tenant. A read-only connection to any tenant (e.g. a Microsoft 365 developer tenant) is enough; pass `skip_configured=false` so nothing is compared with it.
- **Confirming a push isn't tied to the plan you saw.** The agent is told to show the plan and wait for your yes, and MCP clients ask before running these tools, but a call with `confirm=true` runs whatever the current plan is.
- **Not checked for coverage yet:** device configuration templates (Device restrictions, Endpoint protection).
- Runs on macOS only.

## License

MIT, see [LICENSE](LICENSE). mSCP is a project of NIST and its contributors and is installed from its own repository under its own terms. This project isn't affiliated with or endorsed by NIST, Apple or Microsoft.
