#!/usr/bin/env node
/**
 * connected-app-compliance.mjs -- Connected App + ECA "will it break?" scanner
 * =============================================================================
 * Inventories every Connected App (legacy `ConnectedApplication`) and External
 * Client App (`ExternalClientApplication`) in a target org, joins each app to
 * its OAuth metadata + recent OauthToken activity, and answers the practical
 * question: which active apps will fail to authenticate when Salesforce hardens
 * PKCE, refresh-token rotation, and refresh-token validity?
 *
 * IMPORTANT — read-the-XML, not SOQL:
 *   The compliance-relevant flags live in the ConnectedApp metadata XML, NOT
 *   in the standard SOQL surface. Specifically:
 *     - <oauthConfig><isPkceRequired>            (PKCE per-app)
 *     - <oauthConfig><isRefreshTokenRotationEnabled>  (rotation)
 *     - <oauthConfig><callbackUrl>               (auth-code-flow indicator)
 *     - <oauthConfig><isClientCredentialEnabled> (client-creds flow)
 *     - <oauthConfig><isNamedUserJwtEnabled>     (JWT-bearer flow)
 *     - <oauthConfig><isCodeCredentialEnabled>   (code-credential flow)
 *     - <oauthConfig><isConsumerSecretOptional>  (public client → PKCE critical)
 *     - <oauthConfig><scopes>                    (refresh_token in scope set?)
 *     - <oauthPolicy><refreshTokenPolicy>        (zero | infinite | time)
 *     - <oauthPolicy><ipRelaxation>              (ENFORCE | BYPASS_*)
 *   Without --check-metadata, we cannot read these and the verdict will be
 *   limited. Always run --check-metadata for a real "will it break" answer.
 *
 * Usage:
 *   node tools/connected-app-compliance.mjs --org <alias>                       # SOQL-only quick pass
 *   node tools/connected-app-compliance.mjs --org <alias> --check-metadata      # Full XML scan
 *   node tools/connected-app-compliance.mjs --org <alias> --check-metadata --will-break
 *   node tools/connected-app-compliance.mjs --org <alias> --json
 *   node tools/connected-app-compliance.mjs --org <alias> --csv > report.csv
 *
 * Default org: $DEFAULT_SALESFORCE_ORG
 * =============================================================================
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { realError, printDoctor, renderHtml, ENFORCEMENT, countdownLabel, loadConfig } from './lib.mjs';

const NC = '\x1b[0m', BOLD = '\x1b[1m', DIM = '\x1b[2m';
const GREEN = '\x1b[32m', YELLOW = '\x1b[33m', RED = '\x1b[31m', CYAN = '\x1b[36m';

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const argv = (n, fb = null) => { const i = args.indexOf(n); return i >= 0 && i + 1 < args.length ? args[i + 1] : fb; };

// --readiness delegates to the companion mandate-readiness module (the other
// 7 June–July 2026 security mandates beyond Connected Apps). Kept as a separate
// module for maintainability; this flag exposes it as one unified CLI.
if (flag('--readiness')) {
  const { runReadiness } = await import('./mandate-readiness.mjs');
  process.exit(await runReadiness());
}

// --doctor: preflight only — which objects are queryable in this org.
if (flag('--doctor')) {
  const orgs = (argv('--org', process.env.DEFAULT_SALESFORCE_ORG) || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!orgs.length) { console.error('error: pass --org <alias>'); process.exit(1); }
  for (const o of orgs) printDoctor(o);
  process.exit(0);
}

// Multi-org: --org a,b runs the connected-app scan per org as a subprocess (the
// scan body is a top-level script). --readiness has native multi-org diff.
if ((argv('--org', process.env.DEFAULT_SALESFORCE_ORG) || '').includes(',')) {
  const orgs = argv('--org').split(',').map((s) => s.trim()).filter(Boolean);
  const passthru = process.argv.slice(2).filter((a, i, arr) => a !== '--org' && arr[i - 1] !== '--org');
  let worst = 0;
  for (const o of orgs) {
    console.log(`\n\x1b[1m═══ ${o} ═══\x1b[0m`);
    try { execSync(`node "${path.join(path.dirname(new URL(import.meta.url).pathname), 'connected-app-compliance.mjs')}" --org ${o} ${passthru.join(' ')}`, { stdio: 'inherit' }); }
    catch (e) { worst = e.status || 1; }
  }
  process.exit(worst);
}

if (flag('--help') || flag('-h')) {
  console.log(`Usage: connected-app-compliance.mjs [options]

  --readiness          Assess the OTHER 7 Salesforce 2026 security mandates
                       (MFA, phishing-resistant MFA, report step-up, TSP, email
                       domain). Delegates to mandate-readiness.mjs; accepts
                       --export-csv and --export-days. Run with --readiness -h
                       for its full options.

  --all                Run this Connected-App scan AND the --readiness scan.
  --doctor             Preflight: report which objects are queryable in the org.
  --org <a>[,<b>]      Target org(s). Comma-separated runs each (multi-org).
  --check-metadata     Retrieve ConnectedApp metadata XML to read PKCE, refresh-
                       token-rotation, refresh-token-policy, OAuth flows, and
                       IP relaxation. Without this, only SOQL-visible posture
                       is evaluated and the result will under-report.
  --check-pkce         Alias for --check-metadata (backwards compatibility).
  --will-break         Show only apps with recent OAuth activity AND a break-
                       condition rule failing.
  --days N             OauthToken usage window (default 90).
  --filter <verdict>   COMPLIANT | NEEDS_REVIEW | NON_COMPLIANT
  --config <file>      .sfcompliance.json (allowlistApps suppression, etc.)
  --json               Machine-readable output.
  --csv                CSV output (suitable for shipping to a customer).
  --html [file]        Executive HTML scorecard.
  --include-managed    Include managed-package ECAs (default: skip).
  -h, --help           Show this help`);
  process.exit(0);
}

const ORG = argv('--org', process.env.DEFAULT_SALESFORCE_ORG);
if (!ORG) {
  console.error(`${RED}error:${NC} no org specified. Pass --org <alias> or set DEFAULT_SALESFORCE_ORG.`);
  process.exit(1);
}

const CHECK_METADATA = flag('--check-metadata') || flag('--check-pkce');
const JSON_OUT = flag('--json');
const CSV_OUT = flag('--csv');
const FILTER = argv('--filter', null);
const INCLUDE_MANAGED = flag('--include-managed');
const WILL_BREAK_MODE = flag('--will-break');
const USAGE_DAYS = parseInt(argv('--days', '90'), 10);

function sfQuery(soql, useTooling = false) {
  const tooling = useTooling ? '--use-tooling-api' : '';
  const cmd = `sf data query --query "${soql.replace(/\n/g, ' ').replace(/\s+/g, ' ')}" --target-org ${ORG} ${tooling} --json`;
  try {
    const raw = execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 }).toString();
    return JSON.parse(raw.slice(raw.indexOf('{'))).result?.records ?? [];
  } catch (e) {
    console.error(`${RED}SOQL failed:${NC} ${soql.slice(0, 80)}...\n${realError(e)}`);
    return [];
  }
}

// ── Rule catalog ─────────────────────────────────────────────────────────
// Findings are { rule, pass: true|false|null, detail }. pass=null = SKIPPED
// (the rule does not apply or we don't have enough data to score). Skipped
// findings do not influence the verdict.
const RULES = {
  pkce_required: {
    label: 'PKCE required for OAuth (isPkceRequired=true)',
    severity: 'high',
    why: 'When Salesforce auto-enforces PKCE on the authorization-code flow, any client that does not send code_challenge + code_verifier gets invalid_grant. Apps using auth-code flow without PKCE-aware client code stop working.',
  },
  refresh_token_policy_explicit: {
    label: 'Refresh-token policy is explicit (not infinite-by-default)',
    severity: 'high',
    why: 'Apps with no refresh-token expiry (or the org-default with no policy applied) will be force-expired on enforcement. Long-lived refresh tokens are the main carrier of access for service integrations.',
  },
  refresh_token_rotation_enabled: {
    label: 'Refresh-token rotation enabled (isRefreshTokenRotationEnabled=true)',
    severity: 'high',
    why: 'Salesforce hardening guidance and the Mar-2026 partner mandate require refresh-token rotation. When enforced, old refresh tokens become single-use; clients that cache and reuse a refresh token break at next refresh.',
  },
  permitted_users_admin_approved: {
    label: 'Permitted users: Admin-approved only',
    severity: 'med',
    why: 'High-privilege apps should restrict to admin-approved users. Best-practice posture; not a break-condition.',
  },
  no_guest_code_credential_flow: {
    label: 'Guest code-credential flow disabled',
    severity: 'high',
    why: 'IsGuestCodeCredFlowEnabled allows unauthenticated guests to obtain access tokens. Posture issue, not a break-condition.',
  },
  ip_relaxation_enforced: {
    label: 'IP relaxation: enforced (not bypassed)',
    severity: 'med',
    why: 'Bypassing the org Login IP Range is a posture concern; only breaks app auth if a Login IP Range is actually configured and a user falls outside it.',
  },
  client_creds_user_set_when_enabled: {
    label: 'Client-credentials flow has a designated user',
    severity: 'high',
    why: 'Client-credentials flow without a designated low-privilege Salesforce Integration user fails token exchange.',
  },
};

// Rules whose failure means the app authentication WILL break under enforcement
// (vs. posture rules where failure is hygiene). Used by --will-break filter.
const BREAK_CONDITION_RULES = new Set([
  'pkce_required',
  'refresh_token_policy_explicit',
  'refresh_token_rotation_enabled',
  'client_creds_user_set_when_enabled',
]);

// ── Metadata parsing ────────────────────────────────────────────────────
// Returns { isPkceRequired, isRefreshTokenRotationEnabled, callbackUrl,
//           isClientCredentialEnabled, isNamedUserJwtEnabled, isCodeCredentialEnabled,
//           isConsumerSecretOptional, scopes, refreshTokenPolicy, ipRelaxation }
// or null if the XML for this app was not retrieved.
function parseConnectedAppXml(xml) {
  const grab = (tag) => {
    const m = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
    return m ? m[1] : null;
  };
  const grabAll = (tag) => {
    const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, 'g');
    const out = [];
    let m;
    while ((m = re.exec(xml)) !== null) out.push(m[1]);
    return out;
  };
  return {
    isPkceRequired: grab('isPkceRequired') === 'true',
    isRefreshTokenRotationEnabled: grab('isRefreshTokenRotationEnabled') === 'true',
    callbackUrl: grab('callbackUrl') || '',
    isClientCredentialEnabled: grab('isClientCredentialEnabled') === 'true',
    isNamedUserJwtEnabled: grab('isNamedUserJwtEnabled') === 'true',
    isCodeCredentialEnabled: grab('isCodeCredentialEnabled') === 'true',
    isConsumerSecretOptional: grab('isConsumerSecretOptional') === 'true',
    scopes: grabAll('scopes'),
    refreshTokenPolicy: grab('refreshTokenPolicy'),  // "zero" | "infinite" | time strings
    ipRelaxation: grab('ipRelaxation'),               // "ENFORCE" | "BYPASS"
    rawHasPkceTag: /<isPkceRequired>/.test(xml),
    rawHasRotationTag: /<isRefreshTokenRotationEnabled>/.test(xml),
  };
}

// Heuristic: which OAuth flows is this app configured to support? PKCE only
// matters for the authorization-code flow; rotation only matters when refresh
// tokens are in scope.
function detectFlows(meta) {
  if (!meta) return { authCode: null, jwt: null, clientCreds: null, codeCredential: null, hasRefreshScope: null };
  const scopeSet = new Set((meta.scopes || []).map((s) => s.toLowerCase()));
  return {
    authCode: !!meta.callbackUrl,                                  // callbackUrl required for auth-code variants
    jwt: meta.isNamedUserJwtEnabled === true,
    clientCreds: meta.isClientCredentialEnabled === true,
    codeCredential: meta.isCodeCredentialEnabled === true,
    hasRefreshScope: scopeSet.has('refreshtoken') || scopeSet.has('refresh_token') || scopeSet.has('full'),
    publicClient: meta.isConsumerSecretOptional === true,
  };
}

// CLI advisory/error cleanup now lives in lib.mjs (realError / cleanStderr).

// `sf project retrieve start` requires a workspace with an sfdx-project.json
// at the cwd. To make this tool runnable from anywhere (not just inside an
// SFDX project), we create a minimal scratch project in a temp dir and run
// retrieves with `cwd` set to it. Without this, retrieves fail silently with
// InvalidProjectWorkspaceError and the user gets an incomplete report without
// realizing it.
function ensureScratchSfdxProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-cac-project-'));
  fs.writeFileSync(path.join(dir, 'sfdx-project.json'), JSON.stringify({
    packageDirectories: [{ path: 'force-app', default: true }],
    namespace: '',
    sfdcLoginUrl: 'https://login.salesforce.com',
    sourceApiVersion: '60.0',
  }, null, 2));
  fs.mkdirSync(path.join(dir, 'force-app', 'main', 'default'), { recursive: true });
  return dir;
}

function retrieveCAMetadata(devNames) {
  if (!devNames.length) return { map: new Map(), errors: [] };
  const projectDir = ensureScratchSfdxProject();
  // `sf` CLI 2.x rejects --output-dir unless it resolves *inside* the project
  // root (OutputDirOutsideProjectError). On macOS an absolute /tmp path is a
  // symlink to /private/tmp, so the CLI's relative-path check mis-fires even
  // when the dir is genuinely inside projectDir. Pass a RELATIVE output dir
  // (resolved against cwd=projectDir) and keep the absolute path for walking.
  const tmpRel = 'ca-meta';
  const tmp = path.join(projectDir, tmpRel);
  fs.mkdirSync(tmp, { recursive: true });
  console.error(`${DIM}retrieving ConnectedApp metadata for ${devNames.length} apps...${NC}`);

  const chunks = [];
  for (let i = 0; i < devNames.length; i += 100) chunks.push(devNames.slice(i, i + 100));

  const errors = [];
  for (const chunk of chunks) {
    const cmd = `sf project retrieve start ${chunk.map((n) => `--metadata "ConnectedApp:${n}"`).join(' ')} --target-org ${ORG} --output-dir "${tmpRel}" --json`;
    try {
      execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 128 * 1024 * 1024, cwd: projectDir });
    } catch (e) {
      errors.push(realError(e).slice(0, 400));
    }
  }

  const out = new Map();
  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.connectedApp-meta.xml')) {
        const dev = entry.name.replace(/\.connectedApp-meta\.xml$/, '');
        out.set(dev, parseConnectedAppXml(fs.readFileSync(full, 'utf8')));
      }
    }
  }
  walk(tmp);

  // Surface partial-failure visibly: if we asked for N and got back M < N,
  // the user needs to know their report is incomplete.
  if (out.size < devNames.length) {
    console.error(`${YELLOW}warning:${NC} retrieved metadata for ${out.size}/${devNames.length} apps. Apps without retrieved metadata will have PKCE/rotation/policy rules SKIPPED.`);
    if (errors.length) console.error(`${DIM}  first error: ${errors[0].split('\n')[0].slice(0, 200)}${NC}`);
  }
  return { map: out, errors };
}

function retrieveOrgWidePkceSetting() {
  // The org-wide OAuth toggles live in Settings:OauthOidc. The XML root is
  // <OauthOidcSettings> and exposes:
  //   <isPkceRequired>          — org-wide Require PKCE
  //   <blockOAuthUnPwFlow>      — block username/password flow
  //   <blockOAuthUsrAgtFlow>    — block user-agent (implicit) flow
  //   <oAuthCdCrdtFlowEnable>   — allow code-credential flow
  // We pull all four because they all change "what will break" downstream.
  const projectDir = ensureScratchSfdxProject();
  // Output dir must resolve inside the project root, passed relative — see the
  // symlink note in retrieveCAMetadata.
  const tmpRel = 'oidc-settings';
  const tmp = path.join(projectDir, tmpRel);
  fs.mkdirSync(tmp, { recursive: true });
  try {
    execSync(`sf project retrieve start --metadata "Settings:OauthOidc" --target-org ${ORG} --output-dir "${tmpRel}" --json`, { stdio: ['ignore', 'pipe', 'pipe'], cwd: projectDir });
  } catch (e) {
    return { error: realError(e).slice(0, 200) };
  }
  const settingsPath = walkFor(tmp, 'OauthOidc.settings-meta.xml');
  if (!settingsPath) return { error: 'Settings:OauthOidc not retrieved (older org? insufficient permission?)' };
  const xml = fs.readFileSync(settingsPath, 'utf8');
  const grab = (tag) => {
    const m = xml.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
    return m ? m[1] === 'true' : null;
  };
  return {
    isPkceRequired: grab('isPkceRequired'),
    blockOAuthUnPwFlow: grab('blockOAuthUnPwFlow'),
    blockOAuthUsrAgtFlow: grab('blockOAuthUsrAgtFlow'),
    oAuthCdCrdtFlowEnable: grab('oAuthCdCrdtFlowEnable'),
    path: settingsPath,
  };
}

function walkFor(dir, suffix) {
  if (!fs.existsSync(dir)) return null;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const r = walkFor(full, suffix);
      if (r) return r;
    } else if (entry.name.endsWith(suffix)) return full;
  }
  return null;
}

// ── Evaluation ───────────────────────────────────────────────────────────
function evaluateLegacyApp(ca, meta, orgWidePkce) {
  const findings = [];
  const flows = detectFlows(meta);

  // R1: PKCE — applicable only when the app uses authorization-code flow.
  // If org-wide PKCE is on, every app that uses auth-code flow needs it.
  if (meta) {
    if (!flows.authCode) {
      findings.push({ rule: 'pkce_required', pass: null, detail: 'No callbackUrl → authorization-code flow not used; PKCE not applicable' });
    } else if (meta.isPkceRequired) {
      findings.push({ rule: 'pkce_required', pass: true, detail: 'isPkceRequired=true' });
    } else if (orgWidePkce?.isPkceRequired === true) {
      findings.push({ rule: 'pkce_required', pass: false, detail: 'isPkceRequired=false BUT org-wide Require PKCE is ON → token endpoint will reject non-PKCE clients NOW' });
    } else {
      findings.push({ rule: 'pkce_required', pass: false, detail: 'isPkceRequired=false (will fail when org-wide or per-app PKCE enforces)' });
    }
  } else {
    findings.push({ rule: 'pkce_required', pass: null, detail: 'metadata not retrieved (run with --check-metadata)' });
  }

  // R2: Refresh-token rotation — applicable only when refresh_token is in scopes.
  if (meta) {
    if (!flows.hasRefreshScope) {
      findings.push({ rule: 'refresh_token_rotation_enabled', pass: null, detail: 'refresh_token not in scopes → rotation not applicable' });
    } else if (meta.isRefreshTokenRotationEnabled) {
      findings.push({ rule: 'refresh_token_rotation_enabled', pass: true, detail: 'isRefreshTokenRotationEnabled=true' });
    } else {
      findings.push({ rule: 'refresh_token_rotation_enabled', pass: false, detail: 'isRefreshTokenRotationEnabled=false (clients reusing a refresh token will break when rotation enforces)' });
    }
  } else {
    findings.push({ rule: 'refresh_token_rotation_enabled', pass: null, detail: 'metadata not retrieved (run with --check-metadata)' });
  }

  // R3: Refresh-token policy — XML truth wins over SOQL.
  if (meta) {
    if (!flows.hasRefreshScope) {
      findings.push({ rule: 'refresh_token_policy_explicit', pass: null, detail: 'refresh_token not in scopes → policy not applicable' });
    } else if (meta.refreshTokenPolicy === 'infinite') {
      findings.push({ rule: 'refresh_token_policy_explicit', pass: false, detail: 'refreshTokenPolicy=infinite (tokens never expire)' });
    } else if (meta.refreshTokenPolicy) {
      findings.push({ rule: 'refresh_token_policy_explicit', pass: true, detail: `refreshTokenPolicy=${meta.refreshTokenPolicy}` });
    } else {
      findings.push({ rule: 'refresh_token_policy_explicit', pass: null, detail: 'No refreshTokenPolicy in XML' });
    }
  } else {
    // SOQL fallback — only meaningful when OptionsRefreshTokenValidityMetric=true.
    if (ca.OptionsRefreshTokenValidityMetric === true) {
      const ok = ca.RefreshTokenValidityPeriod != null && ca.RefreshTokenValidityPeriod > 0;
      findings.push({
        rule: 'refresh_token_policy_explicit',
        pass: ok,
        detail: ok ? `RefreshTokenValidityPeriod=${ca.RefreshTokenValidityPeriod} (per-app override)` : 'OptionsRefreshTokenValidityMetric=true but no validity period set',
      });
    } else {
      findings.push({
        rule: 'refresh_token_policy_explicit',
        pass: null,
        detail: 'OptionsRefreshTokenValidityMetric=false → app uses org default; cannot tell from SOQL alone',
      });
    }
  }

  // R4: Permitted users (best-practice).
  findings.push({
    rule: 'permitted_users_admin_approved',
    pass: ca.OptionsAllowAdminApprovedUsersOnly === true,
    detail: ca.OptionsAllowAdminApprovedUsersOnly ? 'AdminApprovedUsersOnly=true' : 'AdminApprovedUsersOnly=false',
  });

  // R5: Guest code-credential.
  findings.push({
    rule: 'no_guest_code_credential_flow',
    pass: ca.OptionsCodeCredentialGuestEnabled !== true,
    detail: ca.OptionsCodeCredentialGuestEnabled ? 'CodeCredentialGuestEnabled=true (HIGH RISK)' : 'CodeCredentialGuestEnabled=false',
  });

  // R6: IP relaxation (XML truth).
  if (meta?.ipRelaxation) {
    const enforced = /^ENFORCE/i.test(meta.ipRelaxation);
    findings.push({
      rule: 'ip_relaxation_enforced',
      pass: enforced,
      detail: `ipRelaxation=${meta.ipRelaxation}`,
    });
  } else {
    findings.push({ rule: 'ip_relaxation_enforced', pass: null, detail: 'metadata not retrieved' });
  }

  // R7: Client credentials user (legacy CAs expose this only via metadata, which we don't deeply parse here).
  findings.push({ rule: 'client_creds_user_set_when_enabled', pass: null, detail: 'Legacy CA: not evaluated (would require <permissionSetName> + executionUser metadata)' });

  return { findings, flows };
}

function evaluateECA(_eca, policy) {
  const findings = [];
  const flows = { authCode: true, jwt: false, clientCreds: !!policy?.IsClientCredentialsFlowEnabled, codeCredential: !!policy?.IsGuestCodeCredFlowEnabled, hasRefreshScope: true };

  // ECAs require PKCE by default (per Salesforce ECA design); we mark as PASS
  // unless we can prove otherwise via attribute key/value (not reliable yet).
  findings.push({ rule: 'pkce_required', pass: true, detail: 'ECA — PKCE required by design for the authorization-code flow' });

  // Permitted users — the strict value is AdminApprovedPreAuthorized (verified from picklist describe).
  const permitted = policy?.PermittedUsersPolicyType;
  findings.push({
    rule: 'permitted_users_admin_approved',
    pass: permitted === 'AdminApprovedPreAuthorized',
    detail: `PermittedUsersPolicyType=${permitted ?? 'unset'}`,
  });

  // IP relaxation — picklist values are: 0=Enforce, 1=Relax-for-activated-devices,
  // 2=Relax (full), 3=Enforce-but-relax-for-refresh-tokens. 0 and 3 are enforced;
  // 1 and 2 are relaxed.
  const ip = policy?.IpRelaxationPolicyType;
  const ipEnforced = ip === '0' || ip === '3' || ip === 0 || ip === 3;
  findings.push({
    rule: 'ip_relaxation_enforced',
    pass: ip == null ? null : ipEnforced,
    detail: `IpRelaxationPolicyType=${ip ?? 'unset'} ${ipEnforced ? '(enforced)' : ip != null ? '(relaxed)' : ''}`.trim(),
  });

  // Refresh-token policy — picklist: Infinite, Zero, SpecificLifetime, SpecificInactivity.
  // Anything but Infinite is an explicit policy.
  const rtType = policy?.RefreshTokenPolicyType;
  if (!rtType) findings.push({ rule: 'refresh_token_policy_explicit', pass: null, detail: 'No policy config row' });
  else if (rtType === 'Infinite') findings.push({ rule: 'refresh_token_policy_explicit', pass: false, detail: 'RefreshTokenPolicyType=Infinite (tokens never expire)' });
  else findings.push({ rule: 'refresh_token_policy_explicit', pass: true, detail: `RefreshTokenPolicyType=${rtType}` });

  // Refresh-token rotation — ECAs do NOT encode rotation in RefreshTokenPolicyType
  // (verified from picklist describe). Rotation is a separate setting that we
  // cannot determine from any queryable ECA field today. Mark as SKIPPED rather
  // than guessing — false positives here are worse than gaps.
  findings.push({
    rule: 'refresh_token_rotation_enabled',
    pass: null,
    detail: 'ECA rotation flag is not exposed via any queryable field; cannot evaluate from data alone. Verify in Setup → External Client Apps → app → OAuth Settings.',
  });

  // Guest code-credential
  findings.push({
    rule: 'no_guest_code_credential_flow',
    pass: policy?.IsGuestCodeCredFlowEnabled !== true,
    detail: policy?.IsGuestCodeCredFlowEnabled ? 'IsGuestCodeCredFlowEnabled=true (HIGH RISK)' : 'IsGuestCodeCredFlowEnabled=false',
  });

  // Client-credentials flow user
  if (policy?.IsClientCredentialsFlowEnabled) {
    findings.push({
      rule: 'client_creds_user_set_when_enabled',
      pass: !!policy?.ClientCredentialsFlowUser,
      detail: policy?.ClientCredentialsFlowUser ? `ClientCredentialsFlowUser=${policy.ClientCredentialsFlowUser}` : 'ClientCredentialsFlowEnabled but no user designated',
    });
  } else {
    findings.push({ rule: 'client_creds_user_set_when_enabled', pass: null, detail: 'Client-credentials flow not enabled' });
  }

  return { findings, flows };
}

function verdictForFindings(findings) {
  // pass=null findings are skipped (rule not applicable / not enough data)
  const evaluated = findings.filter((f) => f.pass !== null);
  const failed = evaluated.filter((f) => !f.pass);
  if (failed.length === 0) return 'COMPLIANT';
  const anyHigh = failed.some((f) => RULES[f.rule]?.severity === 'high');
  return anyHigh ? 'NON_COMPLIANT' : 'NEEDS_REVIEW';
}

function willBreakVerdict(report) {
  const breakFails = report.findings.filter((f) => f.pass === false && BREAK_CONDITION_RULES.has(f.rule));
  const hasUsage = (report.usage?.tokenCount ?? 0) > 0;
  if (!hasUsage) return 'DORMANT';
  if (breakFails.length > 0) return 'WILL_BREAK';
  return 'ACTIVE_OK';
}

function colorVerdict(v) {
  if (v === 'COMPLIANT' || v === 'ACTIVE_OK') return `${GREEN}${v}${NC}`;
  if (v === 'NEEDS_REVIEW' || v === 'DORMANT') return `${YELLOW}${v}${NC}`;
  return `${RED}${v}${NC}`;
}

// ── Main ─────────────────────────────────────────────────────────────────
console.error(`${BOLD}Connected App + ECA scan${NC} -- org: ${CYAN}${ORG}${NC}`);

// ConnectedApplication's compliance-relevant fields (ContactEmail, Options*,
// RefreshTokenValidityPeriod) are only accessible via the Tooling API.
const legacyApps = sfQuery(`
  SELECT Id, Name, ContactEmail, Description,
         OptionsAllowAdminApprovedUsersOnly, OptionsRefreshTokenValidityMetric,
         OptionsCodeCredentialGuestEnabled, OptionsTokenExchangeManageBitEnabled,
         OptionsHasSessionLevelPolicy, OptionsIsInternal,
         RefreshTokenValidityPeriod, SessionTimeout,
         CreatedDate, LastModifiedDate
  FROM ConnectedApplication
  ORDER BY Name
`, true).map((r) => ({ ...r, _kind: 'CA', _devName: r.Name?.replace(/[^A-Za-z0-9_]/g, '_') }));

const ecaWhere = INCLUDE_MANAGED ? '' : 'WHERE NamespacePrefix = null';
const ecaApps = sfQuery(`
  SELECT Id, DeveloperName, MasterLabel, ContactEmail, NamespacePrefix,
         DistributionState, ManagedType, Description, CreatedDate, LastModifiedDate
  FROM ExternalClientApplication
  ${ecaWhere}
  ORDER BY MasterLabel
`).map((r) => ({ ...r, _kind: 'ECA', _devName: r.DeveloperName }));

const ecaPolicies = sfQuery(`
  SELECT Id, ExternalClientApplicationId, RefreshTokenPolicyType,
         RefreshTokenValidityPeriod, RefreshTokenValidityUnit,
         IpRelaxationPolicyType, PermittedUsersPolicyType,
         IsClientCredentialsFlowEnabled, ClientCredentialsFlowUser,
         IsTokenExchangeFlowEnabled, IsGuestCodeCredFlowEnabled,
         RequiredSessionLevel
  FROM ExtlClntAppOauthPlcyCnfg
`);
const policyByEca = new Map(ecaPolicies.map((p) => [p.ExternalClientApplicationId, p]));

console.error(`${DIM}found ${legacyApps.length} legacy CAs, ${ecaApps.length} ECAs${NC}`);

// ── Usage signal ────────────────────────────────────────────────────────
console.error(`${DIM}querying OauthToken activity in the last ${USAGE_DAYS} days...${NC}`);
const tokenRows = sfQuery(`
  SELECT AppName, LastUsedDate, UseCount
  FROM OauthToken
  WHERE LastUsedDate >= LAST_N_DAYS:${USAGE_DAYS}
`);
const usageByApp = new Map();
for (const t of tokenRows) {
  const k = t.AppName ?? '';
  const cur = usageByApp.get(k) ?? { tokenCount: 0, useCount: 0, lastUsedDate: null };
  cur.tokenCount += 1;
  cur.useCount += parseInt(t.UseCount ?? 0, 10) || 0;
  if (!cur.lastUsedDate || t.LastUsedDate > cur.lastUsedDate) cur.lastUsedDate = t.LastUsedDate;
  usageByApp.set(k, cur);
}
console.error(`${DIM}${usageByApp.size} distinct apps had OAuth activity${NC}`);

// ── Installed package inventory ─────────────────────────────────────────
// InstalledSubscriberPackage joins to SubscriberPackage (which exposes Name,
// NamespacePrefix, Description). We use this to match each app to its source
// package using three strategies in order:
//   1. NamespacePrefix exact match (CA/ECA's namespace == package namespace)
//   2. App-name substring match (AppName contains package Name, e.g.,
//      "Adobe Acrobat Sign" → package "Adobe Acrobat Sign")
//   3. Namespace-prefix match (AppName starts with `${ns}__`)
// Salesforce-native apps (Salesforce CLI, Heroku Connect, Customer 360 etc.)
// won't match anything — those publish out of Salesforce's own first-party
// connected apps and are not in InstalledSubscriberPackage. We flag them as
// "Salesforce-native" by pattern.
console.error(`${DIM}querying InstalledSubscriberPackage inventory...${NC}`);
const installedPackages = sfQuery(`
  SELECT SubscriberPackage.Name, SubscriberPackage.NamespacePrefix, SubscriberPackage.Description,
         SubscriberPackageVersion.MajorVersion, SubscriberPackageVersion.MinorVersion
  FROM InstalledSubscriberPackage
  ORDER BY SubscriberPackage.Name
`, true).map((r) => ({
  name: r.SubscriberPackage?.Name ?? '',
  namespace: r.SubscriberPackage?.NamespacePrefix ?? '',
  description: r.SubscriberPackage?.Description ?? '',
  version: `${r.SubscriberPackageVersion?.MajorVersion ?? '?'}.${r.SubscriberPackageVersion?.MinorVersion ?? '?'}`,
}));
console.error(`${DIM}${installedPackages.length} managed packages installed${NC}`);

// Patterns for Salesforce-native first-party apps that aren't in
// InstalledSubscriberPackage. Conservative — only apps documented as
// Salesforce-published. Third-party tools like Gearset and the open-source
// Workbench community tool are intentionally NOT in this list; they fall to
// "unknown" so the owner is surfaced as needing manual identification.
const SALESFORCE_NATIVE_PATTERNS = [
  /^Salesforce CLI/i, /^Salesforce Connect$/i, /^Salesforce Compliance Site/i, /^Salesforce for /i,
  /^Customer 360/i, /^CRM Connector for Customer 360/i, /^Chatbots$/i, /^AI Platform Auth/i,
  /^Heroku Connect/i, /^Insights$/i, /^Wave Web/i,
  /^Dataloader (Bulk|Partner)/i, /^TableauID/i, /^Tableau Online for Salesforce/i,
  /^SfdcSIQCloudActivity/i, /^SfdcSiqActivityPlatform/i,
  /^OIQ_/i,                          // Salesforce IQ (legacy RelateIQ acquisition)
  /^apexguru/i,                      // Salesforce ApexGuru
  /^tbid\.digital\.salesforce\.com$/i, // Trailblazer ID (Salesforce-owned login bridge)
];

function classifyPublisher(appName, ca = null) {
  // Strategy 0: app is in our CA/ECA SOQL surface but has no NamespacePrefix
  // → Org-internal (custom-built — not installed from a managed package)
  if (ca && (ca.NamespacePrefix === null || ca.NamespacePrefix === undefined || ca.NamespacePrefix === '')) {
    return { match: 'org-internal', publisher: { name: 'Org-internal (custom-built)', namespace: '', description: '', version: '' } };
  }
  // Strategy 1: CA/ECA namespace exact match
  if (ca?.NamespacePrefix) {
    const pkg = installedPackages.find((p) => p.namespace === ca.NamespacePrefix);
    if (pkg) return { match: 'namespace-exact', publisher: pkg };
  }
  // Strategy 2: App-name contains package Name (case-insensitive)
  const lower = appName.toLowerCase();
  const byNameMatch = installedPackages.find((p) => p.name && lower.includes(p.name.toLowerCase()) && p.name.length > 5);
  if (byNameMatch) return { match: 'name-fuzzy', publisher: byNameMatch };
  // Strategy 3: AppName starts with namespace__
  for (const p of installedPackages) {
    if (p.namespace && (lower.startsWith(`${p.namespace.toLowerCase()}__`) || lower.startsWith(`${p.namespace.toLowerCase()} `))) {
      return { match: 'namespace-prefix', publisher: p };
    }
  }
  // Strategy 4: Salesforce-native pattern
  if (SALESFORCE_NATIVE_PATTERNS.some((re) => re.test(appName))) {
    return { match: 'salesforce-native', publisher: { name: 'Salesforce (first-party)', namespace: '', description: '', version: '' } };
  }
  return { match: 'unknown', publisher: null };
}

// ── Org-wide PKCE setting ───────────────────────────────────────────────
let orgWidePkce = null;
if (CHECK_METADATA) {
  console.error(`${DIM}retrieving org-wide OAuth/OIDC settings...${NC}`);
  orgWidePkce = retrieveOrgWidePkceSetting();
  if (orgWidePkce?.error) console.error(`${YELLOW}org-wide OAuth/OIDC settings:${NC} ${orgWidePkce.error}`);
  else {
    const tag = (b) => b === true ? `${RED}ON${NC}` : b === false ? `${GREEN}OFF${NC}` : `${YELLOW}?${NC}`;
    console.error(`${BOLD}org-wide OAuth/OIDC settings:${NC}`);
    console.error(`  Require PKCE                ${tag(orgWidePkce.isPkceRequired)}`);
    console.error(`  Block OAuth username/pw     ${tag(orgWidePkce.blockOAuthUnPwFlow)}`);
    console.error(`  Block OAuth user-agent      ${tag(orgWidePkce.blockOAuthUsrAgtFlow)}`);
    console.error(`  Allow code-credential flow  ${tag(orgWidePkce.oAuthCdCrdtFlowEnable)}`);
    if (orgWidePkce.isPkceRequired === true) {
      console.error(`  ${RED}→ Every app using auth-code flow without per-app PKCE will FAIL token exchange today.${NC}`);
    }
  }
}

// ── Metadata retrieval (legacy CAs) ─────────────────────────────────────
let metaByDev = new Map();
if (CHECK_METADATA && legacyApps.length) {
  const result = retrieveCAMetadata(legacyApps.map((a) => a._devName));
  metaByDev = result.map;
}

// ── Evaluate ─────────────────────────────────────────────────────────────
const reports = [];

for (const app of legacyApps) {
  const meta = metaByDev.get(app._devName) ?? null;
  const { findings, flows } = evaluateLegacyApp(app, meta, orgWidePkce);
  const usage = usageByApp.get(app.Name) ?? { tokenCount: 0, useCount: 0, lastUsedDate: null };
  const publisher = classifyPublisher(app.Name, app);
  reports.push({ id: app.Id, name: app.Name, devName: app._devName, kind: 'CA', contact: app.ContactEmail, lastModified: app.LastModifiedDate, findings, flows, meta, usage, publisher });
}

for (const eca of ecaApps) {
  const { findings, flows } = evaluateECA(eca, policyByEca.get(eca.Id));
  const usage = usageByApp.get(eca.MasterLabel) ?? { tokenCount: 0, useCount: 0, lastUsedDate: null };
  const publisher = classifyPublisher(eca.MasterLabel, eca);
  reports.push({ id: eca.Id, name: eca.MasterLabel, devName: eca.DeveloperName, kind: 'ECA', contact: eca.ContactEmail, lastModified: eca.LastModifiedDate, findings, flows, meta: null, usage, publisher });
}

// ── Orphan inventory: OauthToken activity that doesn't join to any CA/ECA ──
// These are typically Salesforce-managed first-party apps (Salesforce CLI,
// Heroku Connect, Insights, etc.) or installed managed packages whose CA
// records aren't surfaced via the standard ConnectedApplication SOQL view.
// We can't compliance-score them, but we MUST surface them: they often carry
// the most active production traffic in the org.
const knownAppNames = new Set([
  ...legacyApps.map((a) => a.Name),
  ...ecaApps.map((a) => a.MasterLabel),
]);
for (const [appName, usage] of usageByApp.entries()) {
  if (!knownAppNames.has(appName)) {
    const publisher = classifyPublisher(appName);
    reports.push({
      id: null,
      name: appName,
      devName: null,
      kind: 'UNTRACKED',
      contact: null,
      lastModified: null,
      findings: [{ rule: 'pkce_required', pass: null, detail: publisher.publisher
        ? `Owned by: ${publisher.publisher.name}${publisher.publisher.namespace ? ` (ns=${publisher.publisher.namespace}, v${publisher.publisher.version})` : ''}. Match strategy: ${publisher.match}.`
        : 'Owner not in InstalledSubscriberPackage. Likely a partner-published CA installed via OAuth-only flow (no managed package), or an app authorized from another Salesforce org.' }],
      flows: { authCode: null, jwt: null, clientCreds: null, codeCredential: null, hasRefreshScope: null },
      meta: null,
      usage,
      publisher,
    });
  }
}

for (const r of reports) {
  r.verdict = r.kind === 'UNTRACKED' ? 'UNKNOWN' : verdictForFindings(r.findings);
  r.willBreak = willBreakVerdict(r);
}

// Config allowlist: suppress known-accepted apps (by exact name) so re-runs
// stay signal-rich. .sfcompliance.json → { "allowlistApps": ["My App", ...] }.
const CONFIG = loadConfig(argv('--config', null));
const allowApps = new Set((CONFIG.allowlistApps || []).map((s) => s.toLowerCase()));
let base = allowApps.size ? reports.filter((r) => !allowApps.has((r.name || '').toLowerCase())) : reports;

let filtered;
if (WILL_BREAK_MODE) {
  filtered = base
    .filter((r) => r.willBreak === 'WILL_BREAK' || (r.kind === 'UNTRACKED' && (r.usage?.tokenCount ?? 0) > 0))
    .sort((a, b) => (b.usage?.useCount ?? 0) - (a.usage?.useCount ?? 0));
} else if (FILTER) {
  filtered = base.filter((r) => r.verdict === FILTER);
} else {
  filtered = base;
}

// ── Output ───────────────────────────────────────────────────────────────
const summary = {
  COMPLIANT: reports.filter((r) => r.verdict === 'COMPLIANT').length,
  NEEDS_REVIEW: reports.filter((r) => r.verdict === 'NEEDS_REVIEW').length,
  NON_COMPLIANT: reports.filter((r) => r.verdict === 'NON_COMPLIANT').length,
  UNKNOWN: reports.filter((r) => r.verdict === 'UNKNOWN').length,
  WILL_BREAK: reports.filter((r) => r.willBreak === 'WILL_BREAK').length,
  ACTIVE_OK: reports.filter((r) => r.willBreak === 'ACTIVE_OK').length,
  DORMANT: reports.filter((r) => r.willBreak === 'DORMANT').length,
  UNTRACKED_ACTIVE: reports.filter((r) => r.kind === 'UNTRACKED' && (r.usage?.tokenCount ?? 0) > 0).length,
};

if (JSON_OUT) {
  console.log(JSON.stringify({
    org: ORG,
    scannedAt: new Date().toISOString(),
    usageDays: USAGE_DAYS,
    mode: WILL_BREAK_MODE ? 'will-break' : 'audit',
    metadataChecked: CHECK_METADATA,
    orgWidePkce,
    totals: summary,
    rules: RULES,
    reports: filtered,
  }, null, 2));
  process.exit(0);
}

if (CSV_OUT) {
  const cols = ['verdict', 'willBreak', 'kind', 'name', 'devName', 'contact', 'publisherMatch', 'publisherName', 'publisherNamespace', 'publisherVersion', 'tokenCount', 'useCount', 'lastUsedDate', 'authCodeFlow', 'jwtFlow', 'clientCredsFlow', 'failedRules', 'failedDetails'];
  console.log(cols.join(','));
  for (const r of filtered) {
    const fail = r.findings.filter((f) => f.pass === false);
    const failedRules = fail.map((f) => f.rule).join('; ');
    const failedDetails = fail.map((f) => f.detail).join(' | ').replace(/"/g, '""');
    console.log([
      r.verdict, r.willBreak, r.kind, `"${(r.name ?? '').replace(/"/g, '""')}"`, r.devName ?? '',
      r.contact ?? '',
      r.publisher?.match ?? 'unknown', `"${(r.publisher?.publisher?.name ?? '').replace(/"/g, '""')}"`,
      r.publisher?.publisher?.namespace ?? '', r.publisher?.publisher?.version ?? '',
      r.usage?.tokenCount ?? 0, r.usage?.useCount ?? 0, r.usage?.lastUsedDate ?? '',
      r.flows?.authCode ?? '', r.flows?.jwt ?? '', r.flows?.clientCreds ?? '',
      `"${failedRules}"`, `"${failedDetails}"`,
    ].join(','));
  }
  process.exit(0);
}

// Pretty output
console.error('');
if (WILL_BREAK_MODE) {
  console.error(`${BOLD}Will-Break Scan${NC}  ${DIM}(active in last ${USAGE_DAYS}d + break-condition rules failing)${NC}`);
  console.error(`  ${RED}WILL_BREAK${NC}        ${summary.WILL_BREAK}   ${DIM}(authentication will fail at PKCE / refresh-token enforcement)${NC}`);
  console.error(`  ${YELLOW}UNTRACKED_ACTIVE${NC}  ${summary.UNTRACKED_ACTIVE}   ${DIM}(active OAuth traffic from apps not in the CA/ECA inventory)${NC}`);
  console.error(`  ${GREEN}ACTIVE_OK${NC}         ${summary.ACTIVE_OK}   ${DIM}(active and clean)${NC}`);
  console.error(`  ${DIM}DORMANT${NC}            ${summary.DORMANT}   ${DIM}(no OAuth activity in window — breakage moot)${NC}`);
} else {
  console.error(`${BOLD}Summary${NC}`);
  console.error(`  ${GREEN}COMPLIANT${NC}     ${summary.COMPLIANT}`);
  console.error(`  ${YELLOW}NEEDS_REVIEW${NC}  ${summary.NEEDS_REVIEW}`);
  console.error(`  ${RED}NON_COMPLIANT${NC} ${summary.NON_COMPLIANT}`);
  console.error(`  ${DIM}UNKNOWN${NC}       ${summary.UNKNOWN}   ${DIM}(untracked / managed-package apps with OAuth activity)${NC}`);
  console.error(`  ${DIM}usage breakdown: ${summary.WILL_BREAK} would break, ${summary.ACTIVE_OK} active+ok, ${summary.DORMANT} dormant (last ${USAGE_DAYS}d)${NC}`);
}
if (orgWidePkce && !orgWidePkce.error) {
  const tag = orgWidePkce.isPkceRequired === true ? `${RED}ON${NC}` : orgWidePkce.isPkceRequired === false ? `${GREEN}OFF${NC}` : `${YELLOW}UNKNOWN${NC}`;
  console.error(`  ${DIM}org-wide Require PKCE: ${tag}${NC}`);
}
console.error('');

for (const r of filtered) {
  const verdictTag = WILL_BREAK_MODE ? r.willBreak : r.verdict;
  const flowsStr = r.flows?.authCode === true ? `${DIM}authcode${NC}`
    : r.flows?.jwt === true ? `${DIM}jwt-bearer${NC}`
    : r.flows?.clientCreds === true ? `${DIM}client-creds${NC}`
    : r.flows?.authCode === null ? '' : `${DIM}flow=?${NC}`;
  const usageStr = r.usage?.tokenCount
    ? `${CYAN}active${NC} ${DIM}(${r.usage.tokenCount} tokens, ${r.usage.useCount} uses, last ${r.usage.lastUsedDate?.slice(0, 10)})${NC}`
    : `${DIM}dormant${NC}`;
  console.log(`${colorVerdict(verdictTag)} ${BOLD}${r.name}${NC} ${DIM}[${r.kind}] ${r.devName ?? ''}${NC}  ${flowsStr} ${usageStr}`);
  if (r.publisher?.publisher) {
    const pub = r.publisher.publisher;
    const ver = pub.version && pub.version !== '?.?' ? ` v${pub.version}` : '';
    const ns = pub.namespace ? ` ns=${pub.namespace}` : '';
    console.log(`  ${DIM}publisher: ${CYAN}${pub.name}${NC}${DIM}${ver}${ns} (match: ${r.publisher.match})${NC}`);
  } else if (r.kind === 'UNTRACKED') {
    console.log(`  ${YELLOW}publisher: unknown${NC} ${DIM}— not in InstalledSubscriberPackage; partner-published OAuth-only or cross-org app${NC}`);
  }
  if (r.contact) console.log(`  ${DIM}contact: ${r.contact}${NC}`);
  const fail = r.findings.filter((f) => f.pass === false);
  const skip = r.findings.filter((f) => f.pass === null);
  if (fail.length === 0 && r.kind !== 'UNTRACKED') {
    console.log(`  ${GREEN}all applicable checks passed${NC}${skip.length ? ` ${DIM}(${skip.length} rules N/A or skipped)${NC}` : ''}`);
  } else {
    for (const f of fail) {
      const isBreak = BREAK_CONDITION_RULES.has(f.rule);
      const sevColor = isBreak ? RED : RULES[f.rule]?.severity === 'high' ? RED : YELLOW;
      const breakBadge = isBreak ? `${RED}[BREAKS AUTH]${NC} ` : '';
      console.log(`  ${sevColor}✗${NC} ${breakBadge}${RULES[f.rule]?.label ?? f.rule} — ${DIM}${f.detail}${NC}`);
    }
    for (const f of skip) {
      console.log(`  ${DIM}—${NC} ${DIM}${RULES[f.rule]?.label ?? f.rule}: ${f.detail}${NC}`);
    }
  }
  console.log('');
}

if (!CHECK_METADATA) {
  console.error(`${YELLOW}note:${NC} ran without --check-metadata. PKCE / refresh-token-rotation / refresh-token-policy verdicts default to SKIPPED. Re-run with --check-metadata for the actual answer.`);
}
if (!WILL_BREAK_MODE && summary.WILL_BREAK + summary.UNTRACKED_ACTIVE > 0) {
  console.error(`${YELLOW}tip:${NC} ${summary.WILL_BREAK} apps will break + ${summary.UNTRACKED_ACTIVE} untracked active. Re-run with ${BOLD}--will-break${NC} for the focused list.`);
}

// --html: executive scorecard for the Connected-App scan.
if (flag('--html')) {
  const statusFor = (r) => r.willBreak === 'WILL_BREAK' ? 'WILL_BREAK' : r.verdict;
  const rows = filtered.map((r) => ({
    status: statusFor(r),
    label: `${r.name} [${r.kind}]`,
    enforce: `${ENFORCEMENT.connectedApp} (${countdownLabel(ENFORCEMENT.connectedApp)})`,
    meta: `${r.publisher?.publisher?.name || (r.kind === 'UNTRACKED' ? 'unknown publisher' : '')}${r.contact ? ' · ' + r.contact : ''}`,
    detail: r.findings.filter((f) => f.pass === false).map((f) => (RULES[f.rule]?.label ?? f.rule) + ': ' + f.detail).join(' | ') || (r.kind === 'UNTRACKED' ? 'Untracked active OAuth traffic' : 'All applicable checks passed'),
  }));
  const file = argv('--html', null) || `connected-app-compliance-${ORG}-${new Date().toISOString().slice(0, 10)}.html`;
  fs.writeFileSync(file, renderHtml({ title: 'Connected App / ECA Compliance', org: ORG, generatedAt: new Date().toISOString().slice(0, 19).replace('T', ' '), groups: [{ heading: `Apps (${filtered.length})`, rows }] }));
  console.error(`${CYAN}HTML scorecard →${NC} ${file}`);
}

// --all: chain the readiness scan for the other 7 mandates after this one.
if (flag('--all')) {
  console.error(`\n${BOLD}═══ Other 7 mandates (readiness) ═══${NC}`);
  const { runReadiness } = await import('./mandate-readiness.mjs');
  await runReadiness();
}
