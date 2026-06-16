# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-16

### Fixed

- **`--check-metadata` retrieved 0 apps on Salesforce CLI 2.x (silent).** `sf
  project retrieve start` now rejects `--output-dir` unless it resolves *inside*
  the project root (`OutputDirOutsideProjectError`). The tool created its
  scratch SFDX project in one temp dir but pointed `--output-dir` at a separate
  temp dir, so every retrieve failed — and the real error was masked behind a
  harmless `›  Warning: ... auto-transpiled` line, leaving the tool reporting an
  under-counted `WILL_BREAK` list. On macOS the `/tmp`→`/private/tmp` symlink
  made even an absolute in-project path fail the CLI's relative-path check. Fix:
  pass a **relative** output dir resolved against the scratch-project cwd. Real
  impact on a 76-app org: retrieval went from 0/76 to 72/76, and the verdict
  corrected from 1 to 3 `WILL_BREAK`.

### Added

- **`--readiness` mode (new `mandate-readiness.mjs` module).** Assesses the
  other seven Salesforce June–July 2026 security mandates beyond Connected Apps,
  for the ones measurable from SOQL/metadata:
  - **Phishing-Resistant MFA for Admins** (M1) — privileged-user inventory
    (ModifyAllData/ViewAllData/CustomizeApplication/AuthorApex) cross-referenced
    against registered phishing-resistant methods (`TwoFactorMethodsInfo`
    HasU2F/HasSecurityKey/HasBuiltInAuthenticator).
  - **MFA for All Internal Users** (M2) + **Bypass-MFA exemption holders** (M2b).
  - **Step-Up Auth on Report Actions** (M3) — report-permission users lacking a
    native verification method.
  - **Step-Up on Anomalous Exports** (M4) — `ReportExport` EventLogFile footprint
    (informational; the control itself is ML-driven and unscoreable).
  - **Transaction Security Policy for Reports** (M5) — detects whether a
    qualifying `ReportEvent` TSP exists (else the default auto-applies).
  - **Email Domain Verification** (M8) — `OrgWideEmailAddress.IsVerified` +
    active `EmailDomainKey` DKIM.
  - The two runtime/client-side mandates (anonymizing-IP block + login-anomaly
    containment, and Mobile SDK 13.2.1) are emitted as `MANUAL` with the exact
    Setup location — never fabricated.
  - `--export-csv [file]` writes a per-user remediation list (which users fail
    M1/M2/M3, with profile + privileged flag). CSV output is gitignored by
    default (contains usernames).
  - Every object/field was verified queryable before use. Includes an explicit
    SSO interpretation caveat: IdP MFA can satisfy M2 but NOT M1/M3, and the M1
    set may include API/service accounts (filter the CSV Profile column).

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
