# Settings Catalog mapping

`settings_catalog_map.tsv` (shipped inside the package, read by the tenant coverage check) maps every mSCP rule delivered by a profile or DDM (macOS and iOS/iPadOS, mSCP release_27.0) to Intune Settings Catalog setting definition IDs.

How it was built (2026-10-18, development only, using Lokka against the MacAdmin test tenant; the server itself never calls Lokka):

- **MDM settings**: the definition ID is `<payload type>_<key>`, lowercased, e.g. `com.apple.screensaver` + `askForPassword` → `com.apple.screensaver_askforpassword`.
- **DDM settings**: each declaration type has a group whose `name` is the declaration type (`com.apple.configuration.passcode.settings` → group `passcode_passcode`). Keys sit under that prefix, nested keys joined with `_`, e.g. `intelligencesettings_apps_mail_allowsummary`.
- **No aliases**: `com.apple.screensaver` `idleTime` (device level, what mSCP sets and checks) is not in the catalog; `com.apple.screensaver.user_idletime` is the user channel and doesn't satisfy the rule, so it goes in a custom profile (checked against Graph 2026-10-22).

Each rule has `status`: `mapped` (every key found), `partial`, or `unmapped` (falls back to a custom profile). Unmapped keys keep the ID that was tried (`unmapped_tried`), so a later catalog refresh can recheck them.

Result for release_27.0: macOS 93/152 rules mapped (61%), iOS/iPadOS 128/148 (86%), CIS L1 macOS 33/48.
