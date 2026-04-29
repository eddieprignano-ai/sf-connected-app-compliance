# sf-connected-app-compliance

> Read-only audit of every Connected App and External Client App in a Salesforce
> org. Tells you which ones will fail to authenticate when Salesforce hardens
> PKCE, refresh-token rotation, and refresh-token validity — **and whose
> publisher owns each fix**.

[![npm version](https://img.shields.io/npm/v/sf-connected-app-compliance.svg)](https://www.npmjs.com/package/sf-connected-app-compliance)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/node/v/sf-connected-app-compliance.svg)](https://nodejs.org)

## Why this exists

Salesforce is rolling out mandatory hardening across the OAuth surface:

- **PKCE enforcement** for the authorization-code flow ([docs][pkce-doc]). Org-wide toggle in *Setup → OAuth and OpenID Connect Settings*; per-app toggle on each Connected App.
- **Refresh Token Rotation** as a per-app requirement ([docs][rotation-doc]).
- **Refresh-token validity policy** — tokens with no expiry will be force-revoked. Configure under *Setup → Manage Connected Apps → [app] → OAuth Policies*.
- **AppExchange partner mandate (May 11, 2026)** — partner-owned Connected Apps that don't ship PKCE + refresh-token rotation by that date can be delisted or have their Salesforce interop suspended ([Salesforce ISV Partner Community announcement][partner-mandate]). *Their* failure becomes *your* outage.

The tooling Salesforce ships out-of-the-box is a series of Setup pages — each correct in isolation, but none of them together tell you *"which of my 100+ apps will actually break, who owns the fix, and how active is each one."*

[pkce-doc]: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_pkce.htm&type=5
[rotation-doc]: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_rotate_refresh_tokens.htm&type=5
[partner-mandate]: https://partners.salesforce.com/pdx/s/pcnews/mandatory-security-updates-for-connected-apps-and-ecas-MCFBLDLDQ2TVDZFA22GLAMBVEZGY?language=en_US

### Salesforce's own audit pages

The tool covers the same ground as these Setup pages, plus joins them together:

| Salesforce Setup page | What this tool reads | Link |
|---|---|---|
| Manage Connected Apps | `ConnectedApplication` (Tooling API) | [docs][setup-manage-cas] |
| External Client Apps Manager | `ExternalClientApplication` + `ExtlClntAppOauthPlcyCnfg` | [docs][setup-eca] |
| Connected Apps OAuth Usage | `OauthToken` (last 90d activity) | [docs][setup-oauth-usage] |
| Installed Packages | `InstalledSubscriberPackage` (publisher attribution) | [docs][setup-installed-pkgs] |
| OAuth and OpenID Connect Settings | `Settings:OauthOidc` metadata | [docs][setup-oauth-oidc] |

[setup-manage-cas]: https://help.salesforce.com/s/articleView?id=xcloud.connected_app_manage.htm&type=5
[setup-eca]: https://help.salesforce.com/s/articleView?id=xcloud.external_client_apps_manager.htm&type=5
[setup-oauth-usage]: https://help.salesforce.com/s/articleView?id=xcloud.connected_app_manage_oauth_usage.htm&type=5
[setup-installed-pkgs]: https://help.salesforce.com/s/articleView?id=sf.distribution_installing_packages.htm&type=5
[setup-oauth-oidc]: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_settings.htm&type=5

### Further Salesforce reading

- **All Release Updates** (the auto-enforcement queue) — [Setup help][release-updates]
- **Connected App OAuth flows reference** — [docs][oauth-flows]
- **External Client Apps overview** — [docs][eca-overview]
- **Spring '26 Release Notes — Connected Apps & OAuth** — [release notes][rn-spring26]

[release-updates]: https://help.salesforce.com/s/articleView?id=sf.release_updates.htm&type=5
[oauth-flows]: https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_flows.htm&type=5
[eca-overview]: https://help.salesforce.com/s/articleView?id=xcloud.external_client_apps_overview.htm&type=5
[rn-spring26]: https://help.salesforce.com/s/articleView?id=release-notes.rn_security_connected_apps.htm&type=5

## What it produces

```
Will-Break Scan  (active in last 90d + break-condition rules failing)
  WILL_BREAK         3   (authentication will fail at PKCE / refresh-token enforcement)
  UNTRACKED_ACTIVE   27  (active OAuth traffic from apps not in the CA/ECA inventory)
  ACTIVE_OK          29  (active and clean)
  DORMANT            76  (no OAuth activity in window — breakage moot)
  org-wide Require PKCE: OFF

WILL_BREAK  MyInternalApp  [CA] My_Internal_App  authcode  active (16 tokens, 3,910 uses, last 2026-04-24)
  publisher: Org-internal (custom-built) (match: org-internal)
  contact: admin@example.com
  ✗ [BREAKS AUTH] PKCE required for OAuth — isPkceRequired=false (will fail when org-wide or per-app PKCE enforces)
  ✗ [BREAKS AUTH] Refresh-token rotation enabled — isRefreshTokenRotationEnabled=false
```

Each app gets:

- A **verdict** (`COMPLIANT` / `NEEDS_REVIEW` / `NON_COMPLIANT`) on hardening posture
- A **will-break call** (`WILL_BREAK` / `ACTIVE_OK` / `DORMANT`) cross-referenced
  with `OauthToken` activity in the last N days
- A **publisher attribution** (`org-internal`, `salesforce-native`,
  `namespace-exact`, `namespace-prefix`, `name-fuzzy`, or `unknown`) — so you
  know who owns the fix
- A **rule-by-rule breakdown** with break-condition findings flagged

## Compliance rules

| Rule | What it checks | Source | Salesforce docs |
|------|---|---|---|
| `pkce_required` | App has `isPkceRequired=true` (or auth-code flow not in use, in which case skipped) | `<isPkceRequired>` in `.connectedApp-meta.xml` | [PKCE][pkce-doc] |
| `refresh_token_rotation_enabled` | App has `isRefreshTokenRotationEnabled=true` (skipped if `refresh_token` not in scopes) | `<isRefreshTokenRotationEnabled>` in metadata | [Rotate Refresh Tokens][rotation-doc] |
| `refresh_token_policy_explicit` | App has an explicit refresh-token policy (not `infinite`) | `<refreshTokenPolicy>` in metadata, or `RefreshTokenPolicyType` for ECAs | [Refresh Token Policies](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_refresh_token_policies.htm&type=5) |
| `permitted_users_admin_approved` | App restricts to admin-approved users | `OptionsAllowAdminApprovedUsersOnly` (CA) / `PermittedUsersPolicyType` (ECA) | [Manage Permitted Users](https://help.salesforce.com/s/articleView?id=xcloud.connected_app_manage_users.htm&type=5) |
| `no_guest_code_credential_flow` | Guest code-credential flow disabled | `OptionsCodeCredentialGuestEnabled` / `IsGuestCodeCredFlowEnabled` | [OAuth Authorization Code & Credentials Flow](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_code_credentials_flow.htm&type=5) |
| `ip_relaxation_enforced` | IP relaxation not bypassed | `<ipRelaxation>` in metadata / `IpRelaxationPolicyType` | [Manage IP Restrictions](https://help.salesforce.com/s/articleView?id=xcloud.connected_app_manage_ip.htm&type=5) |
| `client_creds_user_set_when_enabled` | Client-credentials flow has a designated run-as user | `ClientCredentialsFlowUser` (ECA) | [OAuth Client Credentials Flow](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_client_credentials_flow.htm&type=5) |

`pkce_required`, `refresh_token_rotation_enabled`, `refresh_token_policy_explicit`,
and `client_creds_user_set_when_enabled` are **break-condition rules** — failure
on any of these means the app's OAuth will fail under enforcement. Other rules
are best-practice posture.

## Requirements

- **Node.js 18+**
- **Salesforce CLI** (`sf`) installed and authenticated against the target org:
  ```bash
  sf org login web --alias myorg
  ```
- **Read access** to:
  - `ConnectedApplication` (Tooling API)
  - `ExternalClientApplication`, `ExtlClntAppOauthPlcyCnfg`
  - `OauthToken`
  - `InstalledSubscriberPackage` (Tooling API)
  - `Settings:OauthOidc` metadata (for org-wide PKCE toggle)
  - `ConnectedApp` metadata retrieval (for `--check-metadata` mode)

  A user with `View Setup and Configuration` + `Customize Application` typically
  has all of these. A *Salesforce System Administrator* always does.

## Install

**Option 1 — npx (no install, recommended for one-off scans):**

```bash
npx sf-connected-app-compliance --org myorg --check-metadata --will-break
```

`npx` will fetch the package the first time and cache it. No global install required.

**Option 2 — global npm install (for repeated runs):**

```bash
npm install -g sf-connected-app-compliance
sf-connected-app-compliance --org myorg --check-metadata --will-break
```

**Option 3 — clone (for contributors):**

```bash
git clone https://github.com/eddieprignano-ai/sf-connected-app-compliance.git
cd sf-connected-app-compliance
node connected-app-compliance.mjs --org myorg
```

**Option 4 — single-file download (no Node package manager):**

```bash
curl -O https://raw.githubusercontent.com/eddieprignano-ai/sf-connected-app-compliance/main/connected-app-compliance.mjs
node connected-app-compliance.mjs --org myorg
```

## Usage

```bash
# Quick SOQL-only pass — fast, but PKCE/rotation rules will be skipped
node connected-app-compliance.mjs --org myorg

# Full scan with metadata retrieval — answers "what will break"
node connected-app-compliance.mjs --org myorg --check-metadata

# Just the will-break list (active apps + break-condition fails)
node connected-app-compliance.mjs --org myorg --check-metadata --will-break

# Export to CSV for spreadsheet-driven triage
node connected-app-compliance.mjs --org myorg --check-metadata --csv > report.csv

# Machine-readable JSON for downstream tooling
node connected-app-compliance.mjs --org myorg --check-metadata --json
```

### Flags

| Flag | Purpose |
|------|---|
| `--org <alias>` | Target Salesforce org alias (default: `$DEFAULT_SALESFORCE_ORG` env var) |
| `--check-metadata` | Retrieve ConnectedApp metadata XML for full PKCE / rotation / refresh-token-policy / OAuth-flow detection. **Strongly recommended** — without this, the most important rules return SKIPPED. |
| `--will-break` | Filter output to apps with recent OAuth activity AND a break-condition rule failing |
| `--days N` | OauthToken usage window (default: 90) |
| `--filter <verdict>` | Show only `COMPLIANT` / `NEEDS_REVIEW` / `NON_COMPLIANT` |
| `--include-managed` | Include managed-package ECAs (default: skip) |
| `--csv` | CSV output |
| `--json` | JSON output (machine-readable) |
| `-h, --help` | Show help |

### Sample run

```bash
$ node connected-app-compliance.mjs --org production --check-metadata --will-break

Connected App + ECA scan -- org: production
found 76 legacy CAs, 5 ECAs
querying OauthToken activity in the last 90 days...
32 distinct apps had OAuth activity
querying InstalledSubscriberPackage inventory...
47 managed packages installed
retrieving org-wide OAuth/OIDC settings...
org-wide OAuth/OIDC settings:
  Require PKCE                OFF
  Block OAuth username/pw     OFF
  Block OAuth user-agent      OFF
  Allow code-credential flow  OFF
retrieving ConnectedApp metadata for 76 apps...

Will-Break Scan  (active in last 90d + break-condition rules failing)
  WILL_BREAK         3
  UNTRACKED_ACTIVE   27
  ACTIVE_OK          29
  DORMANT            76
  org-wide Require PKCE: OFF
```

## How it answers "will it break"

Two distinct enforcement mechanisms are in play, and the tool models both:

1. **Per-org Release Update (automatic)** — Salesforce auto-enforces the
   PKCE / refresh-token-policy / rotation Release Updates in your org on a
   published date. Apps with the wrong per-app config fail at
   `/services/oauth2/token` with `invalid_grant`. The tool flags these as
   `WILL_BREAK` *if* the app has had recent OAuth activity (no point worrying
   about an app no one uses).

2. **AppExchange partner contractual (May 11, 2026)** — Salesforce can suspend
   non-compliant partner apps' interop with your org. The tool surfaces the
   *publisher* of each app via `InstalledSubscriberPackage`, plus a fuzzy-match
   strategy for apps not in the package surface, so you know which partners
   need outreach.

## Publisher attribution

For each app, the tool tries to match a publisher using these strategies in order:

1. **`org-internal`** — App is in your `ConnectedApplication`/`ExternalClientApplication`
   SOQL surface but has no `NamespacePrefix`. You built it.
2. **`namespace-exact`** — App's `NamespacePrefix` matches an installed package's
   namespace exactly.
3. **`name-fuzzy`** — App name contains an installed package name (e.g.,
   *"Adobe Acrobat Sign"* OAuth app → *"Adobe Acrobat Sign"* package).
4. **`namespace-prefix`** — App name starts with `${namespace}__` or `${namespace} `.
5. **`salesforce-native`** — App name matches a known Salesforce-published
   first-party pattern (Salesforce CLI, Heroku Connect, Customer 360 Data
   Platform, AI Platform Auth, etc.).
6. **`unknown`** — None of the above. These are typically partner-published
   OAuth-only apps (no managed package), or apps authorized from another
   Salesforce org. **These are your partner-outreach targets** for the May 11
   deadline.

## Limitations

- **OauthToken** captures user-grant tokens with refresh tokens. JWT-bearer and
  client-credentials flows may not always populate it; an app that runs
  exclusively as a JWT-bearer integration could appear as `DORMANT` even when
  active. Cross-reference with your own integration-monitoring telemetry.
- **`Settings:OauthOidc`** is the org-wide PKCE toggle source. On older API
  versions or with insufficient permissions, retrieval can fail; the tool
  reports "could not determine" and continues.
- **Refresh-token rotation for ECAs** is not exposed via any queryable field at
  the time of writing. The tool marks the rule as SKIPPED for ECAs and prompts
  the user to verify in Setup. If you find a queryable field for this on a
  newer API version, please file an issue or PR.
- **Org-wide settings retrieval requires an SFDX project root.** The tool
  generates a temp directory for retrieval; if your `sf` CLI version doesn't
  support `--output-dir` outside a project, you may need to run the tool from
  inside an SFDX project directory.
- **Rule heuristics are conservative.** When in doubt, the tool prefers
  SKIPPED over false-FAIL — so the verdict count may understate posture
  risk. The audit was specifically designed to avoid noise.

## Development & contributing

This is a single-file tool — easy to fork, audit, and extend.

```bash
git clone https://github.com/eddieprignano-ai/sf-connected-app-compliance.git
cd sf-connected-app-compliance
node connected-app-compliance.mjs --help
```

Pull requests welcome. If you find:

- A new compliance rule worth adding
- A queryable field for ECA refresh-token rotation
- A publisher pattern that misclassifies (false `salesforce-native` or false
  `unknown`)
- An additional org-wide enforcement toggle (e.g., for new Release Updates)

…please file an issue or PR.

## Security & privacy

- The tool is **read-only**. It runs SOQL queries (`sf data query`) and
  retrieves Salesforce metadata (`sf project retrieve start`). It does not
  modify any Connected App, ECA, setting, or org configuration.
- The tool never sends data anywhere. All output is local stdout / files.
- The tool runs against the org alias *you* authenticate via `sf org login`.
  It cannot exceed the permissions of the user it runs as.
- CSV / JSON output may contain Connected App labels, contact emails, and
  metadata flags. Treat the output the way you would treat a Setup-page
  screenshot — internal use unless you've redacted accordingly.

## License

[MIT](LICENSE) — use it freely. Attribution appreciated but not required.

## Acknowledgments

Built originally to answer one specific operational question: *"if Salesforce
auto-enforces PKCE next quarter, how many of our integrations break?"*
The "will it break" framing — usage signal cross-referenced with break-
condition rules — turned out to be the only framing that produced an
actionable list rather than a 200-line compliance audit no one would read.
