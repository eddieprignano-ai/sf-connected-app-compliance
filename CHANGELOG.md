# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-04-29

### Fixed

- **`--check-metadata` no longer silently fails when run outside an SFDX
  project.** Previously, `sf project retrieve start` requires a workspace with
  an `sfdx-project.json` at the cwd; if the user ran the tool from any other
  directory (the default for most installs), the retrieve threw
  `InvalidProjectWorkspaceError` and the tool returned an incomplete
  `WILL_BREAK` list without flagging that anything had gone wrong. The tool
  now generates a scratch SFDX project in a temp dir and runs retrieves with
  `cwd` set to it.
- **Org-wide `Settings:OauthOidc` retrieval** had the same silent-failure mode
  and is fixed the same way.
- **Partial-retrieval visibility.** When metadata can't be retrieved for some
  apps (managed-package CAs, deleted apps, permission gaps), the tool now
  prints a `warning: retrieved metadata for N/M apps` message instead of
  silently skipping rules.
- **Salesforce CLI advisory leakage.** Stripped `›  Warning: @salesforce/cli
  update available` lines from user-facing error messages.

### Added

- README now links to the canonical Salesforce documentation for every rule
  and Setup page the tool reads, plus the original AppExchange partner
  mandate announcement.

## [0.1.0] - 2026-04-29

Initial public release.

### Features

- Inventories all `ConnectedApplication` and `ExternalClientApplication`
  records in a target Salesforce org.
- Cross-references with `OauthToken` activity in the last N days (default 90)
  to distinguish active apps from dormant ones — only active apps with
  break-condition rule failures are flagged `WILL_BREAK`.
- `--check-metadata` mode retrieves `ConnectedApp` metadata XML to read the
  authoritative compliance flags:
  - `<isPkceRequired>` — PKCE per-app
  - `<isRefreshTokenRotationEnabled>` — refresh-token rotation
  - `<refreshTokenPolicy>` — explicit refresh-token policy (zero / infinite /
    time-based)
  - `<callbackUrl>`, `<isClientCredentialEnabled>`, `<isNamedUserJwtEnabled>`,
    `<isCodeCredentialEnabled>` — OAuth flow detection (so PKCE rules don't
    misfire on JWT-bearer or client-credentials apps)
  - `<ipRelaxation>` — IP relaxation enforcement
- Reads org-wide OAuth toggles from `Settings:OauthOidc`:
  - `isPkceRequired` (org-wide PKCE)
  - `blockOAuthUnPwFlow`, `blockOAuthUsrAgtFlow`, `oAuthCdCrdtFlowEnable`
- Publisher attribution via `InstalledSubscriberPackage` join + name-fuzzy /
  namespace-prefix / Salesforce-native pattern fallbacks. Surfaces who owns
  each fix.
- Output formats: pretty (colorized), CSV, JSON.
- Filters: `--will-break`, `--filter <verdict>`, `--include-managed`,
  `--days N`.

### Compliance rules implemented

- `pkce_required` (break-condition)
- `refresh_token_rotation_enabled` (break-condition)
- `refresh_token_policy_explicit` (break-condition)
- `client_creds_user_set_when_enabled` (break-condition)
- `permitted_users_admin_approved` (posture)
- `no_guest_code_credential_flow` (posture)
- `ip_relaxation_enforced` (posture)

### Known limitations

- ECA refresh-token rotation flag is not exposed via any queryable field at
  release time. Marked as SKIPPED with a Setup-page verification prompt.
- `OauthToken` may not capture JWT-bearer or client-credentials flow activity
  reliably. Active-but-flow-specific apps may appear as `DORMANT`.
- `Settings:OauthOidc` retrieval requires modern API / sufficient permissions.
  Falls back gracefully to "could not determine."
