# Reference

How each part of apple-intune-baseline behaves, in detail. The [README](../README.md) has the overview, install and tool list.

## What the overview means

- **Delivery** comes from mSCP's `mechanism`: `ddm`, `profile`, `script` (no payload), `manual`, or `not_actionable` (inherent, permanent, n/a, supplemental).
- **Verification**: `builtin_compliance` (an Intune toggle covers it), `enforced_not_verified` (delivered by a profile, nothing checks it), `custom_compliance_candidate` (script-only on macOS), `unverifiable`, or `none`.
- **Impact tags** (`breaks_workflows`, `user_visible`, `apple_intelligence`) come from a curated map in `classify.py`, not from mSCP. Treat them as hints and tune them there.
- **Tenant coverage** (`check_tenant_coverage`) checks every Settings Catalog policy, custom profile and compliance policy for the platform, assigned or not, so drafts show up too. Two dimensions per rule:
  - *Enforcement* (profile/DDM rules): `covered_assigned`, `covered_unassigned`, `partial`, `conflict`, `duplicate`, `configured_unverified_value`, `not_configured` or `not_configured_custom_profile_only`. Rules with both a DDM and an MDM form count as covered by either, and `matched_via` says which.
  - *Verification* (rules with a built-in Intune compliance setting, including script rules like SIP): `verified_assigned`, `verified_unassigned`, `compliance_different_value` (e.g. Gatekeeper set to "anywhere", or a shorter minimum password length than the baseline) or `not_verified`. Rules verified here won't need a custom compliance script.
  - The full run lists rule IDs per status, a `needs_attention` list (conflicts, duplicates, partial, weaker compliance values) and each policy once with the baseline rules it contributes; `rule=...` shows only the policies involved in that rule.
  - Custom compliance scripts attached to compliance policies count as verification. Their rules are matched by setting name: an exact mSCP rule ID (what this MCP's own scripts will use), or SIP/Gatekeeper/FileVault/Firewall/stealth mode by keyword for scripts written elsewhere.
  - Settings Catalog option IDs (`..._0`, `..._1`) are decoded to their real values through the setting definition before comparing.
  - On a 403 the Graph client gets a fresh token once and retries, so newly consented permissions (e.g. GroupMember.Read.All after re-running setup) apply without signing out.
  - Not checked yet: device configuration templates (Device restrictions, Endpoint protection).

## OS versions (macOS and iOS/iPadOS 26)

- mSCP's release ships baseline files only for its newest OS (27.0), but its rules carry data for every version mSCP supports: macOS 27.0, 26.0, 15.0 and iOS/iPadOS 27.0, 26.0, 18.0. Pass `os_version` (e.g. `'26'`) to any tool; the default stays the newest.
- The first time a version is asked for, the tool builds all of that platform's baselines for it with **mSCP's own generator** (what `mscp admin baselines` runs), so membership per version, version-specific payloads and references come from mSCP. Run for 27.0 the same code reproduces the bundled files byte for byte. About 8 seconds per platform, then cached in `mscp-baselines/<platform>_<version>/`, rebuilt only when the pinned mSCP release changes.
- 26 differs from 27 where mSCP says so, e.g. CIS L1 26 includes `os_power_nap_disable`; NIST 800-53 Moderate 26 has none of the Apple Intelligence rules. Some benchmarks exist only for 26 so far: CIS for iOS (L1/L2, BYOD/Enterprise), iOS STIG, Indigo, NL MAP-GOV. `list_baselines(os_version='26.0')` lists them.
- Everything else keys on the versioned baseline name, so 26 and 27 never mix: `generated/cis_lvl1_macos_26.0/`, policy names `… - CIS L1 26.0 - …`. The prefix is per baseline, not per version. Target 26 and 27 Macs with Intune assignment filters on OS version.
- A tailored baseline for another version: `tailor_baseline(name, os_version='26')` without `from_baseline` copies its exclusions and added rules onto mSCP's 26 version of the same source, and lists rules that don't exist on 26. Values are shared mSCP customizations, so they apply already. The two versions are then separate files.

## Tailoring

- A tailored baseline is an ordinary mSCP baseline YAML in `mscp-custom/baselines/<name>_<platform>_<version>.yaml`: the rules it keeps per section and the parent's `parent_values`. A `tailoring:` block records the source baseline, the short display name used in policy names, and excluded rules with their reasons (mSCP ignores the extra key).
- A changed value is written with mSCP's own `write_odv_custom_rule` to `mscp-custom/rules/<rule>.yaml`. As in mSCP, it is organization-wide: every baseline in the workspace with that rule uses it, on both platforms. Values are checked against the rule's ODV hint (type, min/max).

## Generating policies

- One Settings Catalog policy per mSCP section, with DDM declarations included (they are Settings Catalog settings). Only rules the catalog can't express go to a custom profile, also one per section. Script, manual and inherent rules are counted, not generated.
- Names: `<Prefix> - <Platform> - <Baseline> <OS version> - <Section> - <Settings Catalog|Custom>`, e.g. `CTSO - macOS - CIS L1 27.0 - System Settings - Settings Catalog`. The prefix is saved per tenant, platform and baseline (see *Name prefixes*).
- Built from the tenant's live setting definitions (`/deviceManagement/configurationSettings`), cached for two weeks in `settings_catalog_definitions.json`: real option IDs, integer vs string, nesting of DDM groups, value ranges. A value outside Intune's range (e.g. a password history above 24) falls back to a custom profile. Settings Intune requires next to the one set (e.g. `EnableFirewall` with any firewall setting) are added with the baseline's value, else the tenant's existing value, else Intune's default, and listed under `added_because_intune_requires`.
- With `skip_configured` (default), rules already configured in the tenant are skipped and listed with the policy that has them; partially configured rules get only the missing settings; rules configured with a different value are not generated (that would be an Intune conflict) and come back under `needs_attention`.
- Output: `tenants/<tenant>/generated/<baseline>/policies/` in the workspace, replaced on each run: one Graph-ready JSON per policy, the `.mobileconfig` for custom profiles, and `plan.json` with the whole report.

- Custom profiles write `com.apple.ManagedClient.preferences` payloads the way mSCP and macOS expect them (`PayloadContent` → domain → `Forced` → `mcx_preference_settings`), one payload per domain; the coverage check reads them the same way. Rules: time server enforce, hot corners, Bluetooth, AdminHostInfo, Gatekeeper re-arm, IR receiver.
- List and dictionary keys several rules add to (`DisabledSystemSettings`, `SkipSetupItems`, `mount-controls` with one media type per rule) collect every rule's items/keys, and live in one custom profile only (the first section that has them; `merged_lists` says where): two profiles setting the same key don't combine on a Mac. The coverage check counts a list as covering a rule when the rule's items are in it.
- Booleans offered as `On`/`Off` or `Yes/No` (e.g. FileVault2 `Enable`, where option `_0` is On) are matched as booleans, both when generating and in the coverage check.
- A saved required value for a setting the baseline sets itself is dropped (the baseline's value always wins), with a note.
- The screen saver idle time is mSCP's device-level `com.apple.screensaver` `idleTime`. Intune's catalog only has the user channel (`com.apple.screensaver.user_idletime`), which isn't what mSCP sets or checks, so it goes in the custom profile.

- Two rules of one baseline that want different values for one setting (mSCP's CMMC/CNSSI/HICP baselines list both smart card trust *high* and *moderate*) are never both delivered, nor overwritten silently: the second is reported with the rule it conflicts with, to tailor one out.
- DDM-only rules whose declaration isn't in the Settings Catalog (sshd and PAM via `services.configuration-files`) can't be sent by Intune; compliance checks them and remediation fixes them with mSCP's scripts instead (`also_scripted`).

### Device requirements (Apple's schema)

Everything is generated as before; what a device needs before a setting applies is reported, from Apple's [device-management](https://github.com/apple/device-management) schema (bundled as `mapping/apple_requirements.json`). Devices that don't meet a requirement report the setting as **Not applicable** in Intune; the policy itself is fine.

- **Newer point release**: a key or declaration introduced after the baseline's `.0`, e.g. on a 26 baseline the intelligence and external-intelligence declarations need **macOS/iOS 26.4**, and `AllowVisualIntelligence` and `Apps.Calendar` need **27.0**.
- **Supervised**: DDM declarations whose allowed enrollments are supervised only (intelligence, external intelligence, software update settings on macOS) and MDM keys marked `supervised` (many iOS restrictions, also in the BYOD baselines). A Mac is supervised only through Automated Device Enrollment, so virtual machines never are.
- **Not supported / removed / deprecated**: e.g. `com.apple.SoftwareUpdate` is deprecated in macOS 26.0 and removed in 27.0 (CIS still sets `ConfigDataInstall`, `AutomaticDownload` and `AutomaticallyInstallAppUpdates` with it).

`generate_policies` returns `device_requirements` (rule, policy, requirement) with plain-language `notes`, writes the detail (including the keys) to `plan.json`, and puts one line in each affected policy's description (`Device requirements: 5 rule(s) need macOS 26.4+; 7 rule(s) need a supervised Mac (otherwise 'Not applicable')`), so it's visible in Intune too.

**Supervised and unsupervised sets** (`unsupervised=true` on `generate_policies` and `push_policies`): the default set is mSCP as it is, for supervised (ADE) devices. The unsupervised variant is a second, complete set for user-enrolled, BYOD and virtual devices, named `<Prefix> - <Platform> - <Baseline> <OS> Unsupervised - <Section> - <Type>` and written to `generated/<baseline>/policies-unsupervised/`, so both can be deployed side by side to different groups. In it, rules whose declaration only applies to supervised devices use their MDM payload instead where mSCP has one and it doesn't need supervision (`switched_to_profile`): the passcode rules (`com.apple.mobiledevice.passwordpolicy`), the Apple Intelligence, Siri and dictation restrictions (`com.apple.applicationaccess`, which also work on 26.0–26.3) and software update download on 26. A payload Apple has removed for the target OS is never chosen (`com.apple.SoftwareUpdate` on 27); deprecated ones are, with a note (`mobiledevice.passwordpolicy` is deprecated in 27). Declaration-only rules stay as they are and keep their requirement. Each set's policy descriptions say which variant it is. Neither set counts the other as coverage (`other_variant_not_counted`); `device_results` reports both, each profile with its `variant`, and flags a device that gets both.

**Heads up**: some payloads mSCP sends with just the rule's key define a whole account on the device. `com.apple.mail.managed` (the iOS Mail and S/MIME rules, e.g. `os_mail_move_messages_disable`) is generated as mSCP has it, `EmailAccountType = EmailTypeIMAP` plus the key, which on its own is an IMAP account without a server. `heads_up` says so, with what to add (or to move the key into the profile that already configures the account), as does a comment in the `.mobileconfig` and the `push_policies` plan. mSCP placeholders (`VPNUUID = "VPNUUID"`) get a heads up too.

Rules that change how people sign in get a heads up as well (`kind: sign_in`), with the baseline's own values: the password policy (macOS: locked for 15 minutes after 5 failed attempts, even with the right password; 15 characters, so shorter existing passwords must be changed; history and expiry; iOS: the device is **erased** after the set number of wrong passcodes) and the login window asking for name and password (people type their account name). Easy to lock yourself out of a test device with; test on one you can recover. Known mSCP payload issues are flagged the same way (`kind: mscp_issue`): mSCP's declaration for `pwpolicy_account_lockout_timeout_enforce` sets `MaximumGracePeriodInMinutes` (the screen-lock grace period per Apple) instead of `FailedAttemptsResetInMinutes`; its MDM payload is right.

## Name prefixes

- One prefix per **tenant + platform + baseline**, so a tenant can hold two baselines on the same platform side by side, e.g. `CIS TST - macOS - CIS L1 27.0 - …` and `NIST TST - macOS - NIST 800-53 Moderate 27.0 - …` while a company evaluates both. Another tenant, or iOS/iPadOS in the same tenant, has its own.
- Nothing falls back to another tenant's, platform's or baseline's prefix. When none is saved, the tool asks and suggests the prefixes already used in that tenant and platform. Every generate and results answer shows `prefix` and `prefix_source`.
- `name_prefixes` lists them, or saves/removes one (`baseline=…, prefix=…`). Changing a prefix doesn't rename what's already in Intune; read those with `prefix=<old>`. Results tools use a given prefix for that call only and don't save it; generate tools save it.
- Side by side: when generating, policies this tool made for *other* baselines in the tenant (names in the tool's pattern with a saved prefix) don't count as coverage, so NIST isn't skipped because CIS TST already sets the same thing. They're listed in `other_baselines_not_counted`. To layer baselines on the same Macs instead, pass `count_other_baselines=true`. Hand-made policies that merely start with the prefix still count.
- Values you give for settings Intune requires next to a baseline's (`required_values`, e.g. the screensaver module) are saved the same way, per tenant, platform and baseline, and listed by `name_prefixes`. Another baseline doesn't inherit them, and the baseline's own value for a setting always wins over a saved one.
- `generate_remediation` and `generate_inventory` take `tenant` too and record it, so pushing to another tenant is blocked until you generate for that one.

## Pushing to Intune

- Pushes exactly the files `generate_policies` wrote (`tenants/<tenant>/generated/<baseline>/policies/`), so what lands in Intune is what was reviewed.
- The plan compares every existing policy with the generated one (`in_intune`: `same` / `differs`): custom profiles as parsed plists (comments don't count), Settings Catalog settings without Intune's IDs, nulls and template references, order-free. Policies that differ and aren't in `replace` are listed in `warnings`, so a regenerated baseline doesn't leave stale policies behind.
- Policies an earlier run of the same baseline (and variant) made that the current run no longer generates (e.g. a section whose settings moved from Settings Catalog to a custom profile) are listed as `no_longer_generated` by `generate_policies` and in the push plan's `warnings`. They are never deleted; the person removes or unassigns them in Intune.
- Blocked when the app registration is read-only, when the files were generated against another tenant, or when a required setting still needs a value. Warns when the files are older than 24 hours.
- A policy whose name already exists is skipped; it is overwritten only when named in `replace`. Errors are per policy, with Graph's message, so one rejected policy doesn't stop the rest. Results go to `push.json` next to the files.
- Everything is created unassigned; assign in Intune, ideally to a pilot group first. Afterwards `check_tenant_coverage` shows the rules as `covered_unassigned`.

## Custom compliance (macOS)

- Selection, per rule: already checked by a compliance policy in the tenant (built-in setting, or a custom script with that rule ID or a matching keyword) → skipped and listed; Intune has a built-in setting (FileVault, Firewall, stealth mode, Gatekeeper, SIP, password rules) → on macOS still checked with mSCP's own check in the script (default), or with `include_builtin=true` set in the policy instead (iOS/iPadOS: always built-in, there's no custom compliance). Why script by default: Intune's built-in password settings make the user set a new password right away, while the script only reports; and a user-enrolled macOS 26.6 VM evaluated only the built-in part of a policy that had both, reporting Compliant while a script check failed (script-only policies worked on the same Mac). A rule without an mSCP check keeps its built-in setting; reads the last logged-in user's settings → left out unless `include_per_user`; sections in `merge` (default Auditing) → one String setting `<section>_failed_checks` listing failing rules, which Company Portal shows via `{ActualValue}`.
- The discovery script has a bash shebang (Intune requires it) and hands mSCP's `check` text, unchanged, to zsh as an argument with stdin closed. Each check's output is compared with `result_value` as text, like mSCP's own compliance script; architecture tags are honoured. It prints one line of JSON and changes nothing. Setting names are the mSCP rule IDs, so `check_tenant_coverage` matches them exactly.
- Uses `read -d ''` rather than `$(cat <<…)` for the embedded script: bash 3.2 on macOS misparses quotes inside the latter.
- Graph: scripts go to `/deviceManagement/deviceComplianceScripts` with `platform: macOS`, `runAsAccount: system`; the policy references the script ID plus base64 rules JSON. Needs `DeviceManagementScripts.ReadWrite.All` (part of the `full` permission set; re-run `setup_app_registration` after upgrading).
- `grace_period_hours` (default 0) sets when a failing Mac becomes non-compliant. Test a script on a Mac first: `sudo env -i /bin/bash <file>.sh` should print one JSON line.

## Remediation (macOS)

- For mSCP's `Script` rules (launchd services, sudoers, file permissions, pmset…), which no Settings Catalog policy or custom profile can set. Profile and DDM rules are left to the policies.
- Per rule the script runs mSCP's `check`; only if it fails, mSCP's `fix` unchanged, in a subshell with stdin closed; then the check again. A Mac that already passes is not touched, so the script can run on a schedule (`frequency`: `daily` by default, `weekly` or `once`) and undo drift.
- Log: `/Library/Logs/apple-intune-baseline/<script>.log` (each fix's output, ok / fixed / still failing). Stdout is one summary line. Exit code 1 while a rule still fails, so Intune shows the run as failed; Intune then drops stdout and keeps only stderr (`errorDescription`), so a failing run prints the summary there too. A run that dies before its summary reports which rule it was on (`error: stopped before finishing, during <rule>`). Some fixes (launchd services) only take effect after a restart.
- Left out, with the reason: rules that need macOS Recovery or SIP off (`csrutil`, `nvram`); fixes that install updates or may restart (`include_disruptive` to add; DDM update enforcement does this better); fixes on the last logged-in user (`include_per_user`); rules without an mSCP fix; anything in `exclude`.
- Graph: `/deviceManagement/deviceShellScripts`, `runAsAccount: system`, notifications hidden, no retries. Same name standard with `Remediation`. Test first: `sudo env -i /bin/bash <file>.sh`.
- A few profile-delivered rules are remediated too because the profile doesn't fully enforce them (`also_scripted` says why). Today: `os_unlock_active_user_session_disable` - with Platform SSO, `system.login.screensaver` points at `psso-screensaver` (owner or admin), which `screenUnlockMode` doesn't change; mSCP's fix writes an owner-only copy. `include=[...]` adds other profile rules that have an mSCP fix.

## Device results and reports

- Finds this baseline's compliance policies and remediation scripts by their name prefix, then reads each Mac's state per policy, its setting results and the scripts' run states. Custom compliance settings are mSCP rule IDs already; built-in ones (e.g. `NumberOfPasswordsToRemember`) are mapped back to their rule.
- **Stale**: a policy result older than the last remediation run of the same section, or older than 24 hours. Intune keeps the previous result until the discovery script runs again, so a fixed Mac can look non-compliant for hours; Company Portal → Check status refreshes it.
- Export goes to `tenants/<tenant>/reports/<baseline>/` in the workspace: an interactive HTML dashboard (one self-contained file, works offline: KPI tiles, device status, compliance per section and most failing checks as charts you click through to the Macs behind them; search by name, serial or user; filter by status, section, or any deployed check passing/failing; expand a Mac for every check and its remediation runs; a Checks tab with pass rates per check; export the filtered view as CSV; light and dark), a PDF (summary, most failing checks, a section per Mac with policies, failing rules and remediation runs) and a CSV with one row per Mac and failing check (or per policy when all pass), UTF-8 with BOM for Excel.
- Needs `DeviceManagementManagedDevices.Read.All` (read-only, in both permission sets; re-run `setup_app_registration` after upgrading). `max_devices` (default 50) caps the Graph calls; `device` filters by name or serial.
- **Configuration profiles** (`include=["profiles"]`, on by default next to `"compliance"`): per device, every Settings Catalog policy of the baseline with its settings counted by result, and each setting that didn't succeed with Intune's error code; per custom profile whether it's installed. Settings a device requirement from `plan.json` explains (needs a supervised Mac, a newer point release) or that Intune marks deprecated carry `expected`, so on an unsupervised VM the software update declaration's errors read as expected and only `unexplained` ones need a look. Reads Intune's reports API (`getConfigurationPolicyDevicesReport`, `getConfigurationSettingsReport`: POST, read-only). Not in the exports yet.

## Inventory via custom attributes (macOS)

- Data, not compliance: per mSCP section one custom attribute (string) whose value is one flat line: `rule_id=raw check output; rule_id=…; collected=<UTC time>`. Every rule with an mSCP check is included, also those that profiles enforce, so a CMDB sees what the Mac actually has. Per-user checks only with `include_per_user`.
- One attribute per section rather than per rule: Intune runs each custom attribute every 8 hours and allows 20 KB per value. Values are kept to one line (multi-line output joined with ` | `, max 200 characters per rule); a section over the limit reports `error=…` instead.
- Not JSON: Intune's service rejects custom attribute values that look like JSON: `{"ssh":"PASS"}` fails with `0x87D32710`, while the Mac's agent still logs the run as a success. Inside values `"` becomes `'`, `{ <` become `(`, `} >` become `)` and `;` becomes `,`, so the line splits on `; ` and the first `=`.
- `<name>.fields.json` next to each script: per rule the title, section, mSCP's expected value, organization-defined value and delivery, so the raw values can be read without mSCP.
- Attribute names: `<prefix>_mscp_<section>` (letters, digits, underscores), e.g. `contoso_mscp_system_settings`. Graph: `/deviceManagement/deviceCustomAttributeShellScripts`, `runAsAccount: system`.
- Replacing an existing attribute updates only its script: Intune accepts `{"@odata.type", "scriptContent"}` on update and answers 400 to any body that also has the description, display name, file name or scope tags. Name and description stay as they were created; assignments are kept.
- `inventory_results` reads the run states (`resultMessage` is the value) and compares each value with what mSCP's check prints when the rule is met: `matches`, `differs`, `no value` (the check printed nothing, usually a setting that isn't managed or a source such as a DDM state file without that key) or `not applicable` (other architecture). This is for reading values, not a compliance verdict. The answer is a summary per Mac: counts, the rules that differ (value and expectation) and the ones with no value; pass `rules=[...]` to see specific values.
- **`possibly_outdated`** per Mac and section, from Intune's times only (the Mac's own `collected` clock can be off): the value was reported before this baseline's configuration profiles last changed in Intune (either variant), so it may predate the profile on the Mac, or there's been no report for over 24 hours. Custom attributes run on Intune's schedule, not at every check-in, so a fresh push shows old values for a while.
- Base64 checks (login window text) print `base64(text + newline)`, so the expected value is encoded the same way, and `readable` holds the decoded text.
- Intune returns `customAttributeName` as null, so `attribute` falls back to the name this tool gave it.
- Exports: CSV (one row per Mac and rule, with `value`, `readable`, `mscp_expected`, `compared`, `delivery`), JSON (per Mac, plus the field dictionary) and HTML: a self-contained report in the compliance dashboard's style with a donut, per-section bars and the most-differing rules, a values table (search; filter by result, section and Mac), a rules table with the values seen, a Macs table, CSV export of the current view and light/dark.

- A section whose line could pass 20 KB in the worst case (every value at its cap) is split into several attributes, `… - Operating System (1/2) - Inventory`; results still group by the real section.

## How the scripts run mSCP's text

Discovery, remediation and inventory scripts share one shape: a bash wrapper (Intune needs a shebang) hands the body to zsh with stdin closed. Each check and fix is a zsh function whose body is mSCP's text as a quoted string run with `eval`, so heredocs (`<< EOS`) work exactly as written, even one missing its terminator.

## Workspace

Everything lives in `~/.apple-intune-baseline` (override with `APPLE_INTUNE_BASELINE_HOME`). Its `mscp-custom/` folder is mSCP's own custom directory, so anything tailored stays in mSCP's format. Making the workspace a git repo is recommended.

```
~/.apple-intune-baseline/
├── tenants.json, settings.json, auth/          shared: tenants, sign-ins, prefixes, saved values
├── settings_catalog_definitions.json           shared: cache of Intune's setting definitions
├── mscp-custom/                                shared: tailored baselines and values (mSCP format)
└── tenants/
    └── <tenant>/
        ├── generated/
        │   └── <baseline>/                     e.g. contoso_cis_lvl1_macos_27.0
        │       ├── policies/                   generate_policies
        │       ├── compliance/                 generate_compliance
        │       ├── remediation/                generate_remediation
        │       └── inventory/                  generate_inventory
        └── reports/
            └── <baseline>/                     <baseline>_compliance_<UTC time>.html|pdf|csv
                                                <baseline>_inventory_<UTC time>.html|csv|json
```

The baseline sits above the type, so one evaluation (e.g. NIST next to CIS in the same tenant) is one folder. Pushing reads the target tenant's own folder: files generated for one tenant can't be pushed to another.
