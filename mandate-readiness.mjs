#!/usr/bin/env node
/**
 * sf-security-mandate-readiness
 *
 * Companion to connected-app-compliance.mjs. Where that tool covers the
 * Connected App / ECA OAuth hardening mandate, this one assesses the OTHER
 * Salesforce June–July 2026 security mandates that are measurable from
 * SOQL / metadata:
 *
 *   Mandate 1  Phishing-Resistant MFA for Admins      (Jul 1)   — ASSESSABLE
 *   Mandate 2  MFA for All Internal Users             (Jul 20)  — ASSESSABLE
 *   Mandate 3  Step-Up Auth on Report Actions         (Jul 1)   — PARTIAL
 *   Mandate 4  Step-Up Auth on Anomalous Exports      (Jul 13)  — FOOTPRINT-ONLY
 *   Mandate 5  Transaction Security Policy (Reports)   (Jul 13)  — ASSESSABLE
 *   Mandate 6  Block Anonymizing Proxies / High-Risk IP (live)  — MANUAL/CONFIG
 *   Mandate 7  Login Anomaly Auto-Containment          (live)   — MANUAL/CONFIG
 *   Mandate 8  Email Domain Verification               (live)   — ASSESSABLE
 *
 * Every field/object used here was verified to exist and be queryable in
 * VivintProd before being written. Checks that cannot be grounded in data are
 * emitted as MANUAL with the exact Setup location — never fabricated.
 *
 * IMPORTANT INTERPRETATION NOTE: in SSO orgs, users often have no Salesforce-
 * native verification method because the IdP handles MFA. For Mandate 2 the
 * IdP AMR/ACR signal can satisfy the requirement (verify the signal). For
 * Mandates 1 and 3 the IdP MFA does NOT count — a native passkey / hardware
 * key must be registered per user — so those gaps are real regardless of SSO.
 *
 * Read-only. Requires an authenticated `sf` CLI session.
 *
 * Usage:
 *   node mandate-readiness.mjs --org <alias> [--json] [--export-csv [file]] [--export-days N]
 */

import { execSync } from 'child_process';
import { writeFileSync } from 'fs';
import { pathToFileURL } from 'url';

const C = { red: '\x1b[31m', yel: '\x1b[33m', grn: '\x1b[32m', cyn: '\x1b[36m', dim: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m' };
const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const val = (n, d) => { const i = args.indexOf(n); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : d; };

const PRIV_PERMS = ['PermissionsModifyAllData', 'PermissionsViewAllData', 'PermissionsCustomizeApplication', 'PermissionsAuthorApex'];

function soql({ q, tooling = false }, ORG) {
  const cmd = `sf data query --query "${q.replace(/\s+/g, ' ').trim()}" --target-org ${ORG} ${tooling ? '--use-tooling-api' : ''} --json`;
  const raw = execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }).toString();
  return JSON.parse(raw.slice(raw.indexOf('{'))).result?.records ?? [];
}
function safe(fn, fallback, jsonOut) {
  try { return fn(); }
  catch (e) {
    const msg = (e.stderr?.toString() || e.message || '').split('\n').find((l) => /No such|ERROR|INVALID/i.test(l)) || (e.message || '').slice(0, 120);
    if (!jsonOut) console.error(`${C.dim}  (query failed: ${msg})${C.x}`);
    return fallback;
  }
}
const csvCell = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

export async function runReadiness() {
  const ORG = val('--org', process.env.DEFAULT_SALESFORCE_ORG || '');
  const JSON_OUT = flag('--json');
  const EXPORT_CSV = flag('--export-csv');
  const EXPORT_DAYS = parseInt(val('--export-days', '30'), 10);
  if (!ORG) { console.error('error: pass --org <alias> (or set DEFAULT_SALESFORCE_ORG)'); return 1; }
  if (flag('-h') || flag('--help')) {
    console.log(`Usage: mandate-readiness.mjs --org <alias> [--json] [--export-csv [file]] [--export-days N]
  Assesses the 7 Salesforce 2026 security mandates beyond Connected Apps.
  --org <alias>        Target org (default: $DEFAULT_SALESFORCE_ORG)
  --export-csv [file]  Write per-user remediation list (default: mandate-gaps-<org>-<date>.csv)
  --export-days N      ReportExport EventLogFile window (default 30)
  --json               Machine-readable output`);
    return 0;
  }

  const sq = (o) => soql(o, ORG);
  const sf = (fn, fb) => safe(fn, fb, JSON_OUT);
  if (!JSON_OUT) console.error(`${C.dim}assessing security-mandate readiness — org: ${C.cyn}${ORG}${C.x}`);

  const report = { org: ORG, scannedAt: new Date().toISOString(), exportDays: EXPORT_DAYS, mandates: [] };
  const push = (m) => report.mandates.push(m);

  /* All active internal (Standard) users — basis for gap user-lists + CSV. */
  const usersRaw = sf(() => sq({ q: `SELECT Id, Name, Username, Profile.Name FROM User WHERE IsActive=true AND UserType='Standard'` }), []);
  const userMap = new Map(usersRaw.map((u) => [u.Id, { id: u.Id, name: u.Name, username: u.Username, profile: u.Profile?.Name || '' }]));
  const allStandard = new Set(userMap.keys());

  const privUsers = sf(() => new Set(sq({ q: `SELECT AssigneeId FROM PermissionSetAssignment WHERE (${PRIV_PERMS.map((p) => `PermissionSet.${p}=true`).join(' OR ')}) AND Assignee.IsActive=true AND Assignee.UserType='Standard'` }).map((r) => r.AssigneeId)), new Set());
  const reportUsers = sf(() => new Set(sq({ q: `SELECT AssigneeId FROM PermissionSetAssignment WHERE (PermissionSet.PermissionsRunReports=true OR PermissionSet.PermissionsExportReport=true) AND Assignee.IsActive=true AND Assignee.UserType='Standard'` }).map((r) => r.AssigneeId)), new Set());
  const prMethodUsers = sf(() => new Set(sq({ q: `SELECT UserId FROM TwoFactorMethodsInfo WHERE HasU2F=true OR HasSecurityKey=true OR HasBuiltInAuthenticator=true` }).map((r) => r.UserId)), new Set());
  const anyMethodUsers = sf(() => new Set(sq({ q: `SELECT UserId FROM TwoFactorMethodsInfo WHERE HasU2F=true OR HasSecurityKey=true OR HasBuiltInAuthenticator=true OR HasSalesforceAuthenticator=true OR HasTotp=true OR HasUserVerifiedMobileNumber=true OR HasUserVerifiedEmailAddress=true` }).map((r) => r.UserId)), new Set());

  // Gap user-id lists (the actual remediation targets).
  const gapM1 = [...privUsers].filter((u) => !prMethodUsers.has(u));        // admins w/o phishing-resistant
  const gapM2 = [...allStandard].filter((u) => !anyMethodUsers.has(u));     // any internal w/o any native method
  const gapM3 = [...reportUsers].filter((u) => !anyMethodUsers.has(u));     // report users w/o any native method

  /* ── Mandate 1: Phishing-Resistant MFA for Admins ── */
  push({
    id: 1, title: 'Phishing-Resistant MFA for Admins', enforce: 'Prod Jul 1 2026', status: 'ASSESSABLE',
    metrics: { privilegedUsers: privUsers.size, withPhishingResistantMethod: privUsers.size - gapM1.length, gap: gapM1.length },
    verdict: gapM1.length === 0 ? 'READY' : 'GAP',
    detail: `${gapM1.length}/${privUsers.size} privileged (MAD/VAD/CustomizeApp/AuthorApex) active users have NO phishing-resistant method (U2F/passkey/built-in). TOTP & Salesforce Authenticator do NOT qualify. IdP MFA does NOT satisfy this — gap is real even under SSO. CAVEAT: this set includes API/service accounts (which log in via OAuth/JWT, not interactive MFA) — filter the Profile column in --export-csv to isolate the genuinely interactive human admins, who are the true Jul-1 deadline.`,
    checklistQ: ['Q1', 'Q6', 'Q7'],
  });

  /* ── Mandate 2: MFA for All Internal Users ── */
  push({
    id: 2, title: 'MFA for All Internal Users', enforce: 'Prod Jul 20 2026', status: 'ASSESSABLE',
    metrics: { activeInternalUsers: allStandard.size, withAnyMethodRegistered: anyMethodUsers.size, notEnrolled: gapM2.length },
    verdict: gapM2.length === 0 ? 'READY' : 'GAP',
    detail: `${gapM2.length} of ${allStandard.size} active internal users have no Salesforce-registered method. SSO users MAY still pass via IdP AMR/ACR — verify the IdP signal (manual). Front-line/no-smartphone users are highest lockout risk.`,
    checklistQ: ['Q3', 'Q8'],
  });

  const waiveHolders = sf(() => sq({ q: `SELECT COUNT(Id) c FROM PermissionSetAssignment WHERE PermissionSet.PermissionsBypassMFAForUiLogins=true AND Assignee.IsActive=true` })[0]?.c ?? 0, null);
  push({
    id: '2b', title: 'MFA Exemption Holders (Bypass MFA for UI Logins)', enforce: 'Restricted after Jul 20', status: 'ASSESSABLE',
    metrics: { bypassMfaAssignments: waiveHolders },
    verdict: waiveHolders === 0 ? 'READY' : 'REVIEW',
    detail: `${waiveHolders} active assignment(s) of "Bypass MFA for UI Logins". Each must be justified (automation users only) and will require a Salesforce Case to retain post-enforcement.`,
    checklistQ: ['Q5'],
  });

  /* ── Mandate 3: Step-Up Auth on Report Actions ── */
  push({
    id: 3, title: 'Step-Up Auth on Report Actions', enforce: 'Prod Jul 1 2026', status: 'PARTIAL',
    metrics: { reportRunningUsers: reportUsers.size, withoutAnyNativeMethod: gapM3.length },
    verdict: gapM3.length === 0 ? 'READY' : 'GAP',
    detail: `${gapM3.length}/${reportUsers.size} report-running users have no Salesforce-native method. Step-up does NOT accept Enterprise-IdP MFA; users with no native method get challenged (email step-up auto-enrolls at first challenge per the Jun 11 update, but no valid email = lockout).`,
    checklistQ: ['Q15', 'Q16'],
  });

  /* ── Mandate 5: Transaction Security Policy for Report Exports ── */
  const reportTsp = sf(() => sq({ q: `SELECT DeveloperName, EventName, State FROM TransactionSecurityPolicy WHERE EventName='ReportEvent'`, tooling: true }), []);
  push({
    id: 5, title: 'Transaction Security Policy for Report Exports', enforce: 'Prod Jul 13 2026', status: 'ASSESSABLE',
    metrics: { qualifyingReportEventTSPs: reportTsp.length },
    verdict: reportTsp.length > 0 ? 'READY' : 'DEFAULT_WILL_APPLY',
    detail: reportTsp.length > 0
      ? `${reportTsp.length} ReportEvent TSP(s) configured (${reportTsp.map((t) => t.DeveloperName + ':' + t.State).join(', ')}).`
      : `No qualifying ReportEvent TSP exists — Salesforce auto-adds a DEFAULT policy prompting step-up at >10,000-row exports. Configure your own to control thresholds/exemptions. Requires Shield or Event Monitoring.`,
    checklistQ: ['Q18', 'Q20'],
  });
  const tspExempt = sf(() => sq({ q: `SELECT COUNT(Id) c FROM PermissionSetAssignment WHERE PermissionSet.PermissionsTransactionSecurityExempt=true AND Assignee.IsActive=true` })[0]?.c ?? 0, null);

  /* ── Mandate 4: Step-Up on Anomalous Exports (footprint only) ── */
  const exportFootprint = sf(() => sq({ q: `SELECT COUNT(Id) c FROM EventLogFile WHERE EventType='ReportExport' AND LogDate=LAST_N_DAYS:${EXPORT_DAYS}` })[0]?.c ?? 0, null);
  push({
    id: 4, title: 'Step-Up Auth on Anomalous Report Exports', enforce: 'Prod Jul 13 2026', status: 'FOOTPRINT-ONLY',
    metrics: { reportExportLogFiles: exportFootprint, tspExemptHolders: tspExempt },
    verdict: 'INFORM',
    detail: `ML-driven; no admin-visible config or risk score, so readiness cannot be scored. Footprint: ${exportFootprint} ReportExport EventLogFile(s) in last ${EXPORT_DAYS}d → scripted/scheduled exports exist and may trip the model with no warning. Review headless/integration export jobs for a fallback path.`,
    checklistQ: ['Q17', 'Q18'],
  });

  /* ── Mandate 8: Email Domain Verification ── */
  const owea = sf(() => sq({ q: `SELECT Address, IsVerified, DisplayName FROM OrgWideEmailAddress` }), []);
  const dkim = sf(() => sq({ q: `SELECT Domain, IsActive FROM EmailDomainKey` }), []);
  const unverified = owea.filter((a) => a.IsVerified === false);
  const activeDkim = [...new Set(dkim.filter((d) => d.IsActive).map((d) => d.Domain))];
  push({
    id: 8, title: 'Email Domain Verification', enforce: 'Already in effect', status: 'ASSESSABLE',
    metrics: { orgWideAddresses: owea.length, unverifiedAddresses: unverified.length, activeDkimDomains: activeDkim },
    verdict: unverified.length === 0 ? 'READY' : 'GAP',
    detail: unverified.length === 0
      ? `All ${owea.length} org-wide email addresses verified; active DKIM on: ${activeDkim.join(', ') || 'none'}. Does not cover every flow/Apex sending domain — verify domain-level allowlist separately, incl. sandboxes.`
      : `${unverified.length} unverified org-wide address(es): ${unverified.map((a) => a.Address).join(', ')}. Unverified senders will be blocked.`,
    checklistQ: ['Q13', 'Q14'],
  });

  /* ── Mandates 6 + 7: Anomaly & Containment (config/runtime — MANUAL) ── */
  push({
    id: '6+7', title: 'Anonymizing-IP Block + Login-Anomaly Auto-Containment', enforce: 'Already in effect', status: 'MANUAL', metrics: {}, verdict: 'MANUAL',
    detail: `Runtime ML — not scoreable from SOQL. MANUAL: (a) Setup → Company Information → set a Security Contact distribution list so containment emails land [Q10]; (b) name an owner + unfreeze/reset runbook for "Salesforce Security Notification" emails [Q9]; (c) request Support exemptions for service/integration users egressing via VPN/cloud IPs [Q11]; (d) reconcile new platform detections with existing Shield Threat Detection alerts [Q12].`,
    checklistQ: ['Q9', 'Q10', 'Q11', 'Q12'],
  });
  push({
    id: '6.mobile', title: 'Mobile SDK 13.2.1 cutover (Domain 6)', enforce: 'with PRMFA', status: 'MANUAL', metrics: {}, verdict: 'MANUAL',
    detail: `Client-side; not queryable. MANUAL: confirm any in-house app on Salesforce Mobile SDK is ≥13.2.1 (older WebView mode breaks phishing-resistant MFA); verify InTune/Edge auth path for Salesforce Mobile on iOS [Q24, Q25].`,
    checklistQ: ['Q24', 'Q25'],
  });

  /* ── CSV export: per-user remediation list ── */
  let csvPath = null;
  if (EXPORT_CSV) {
    const inM1 = new Set(gapM1), inM2 = new Set(gapM2), inM3 = new Set(gapM3);
    const ids = new Set([...gapM1, ...gapM2, ...gapM3]);
    const rows = [['User Id', 'Name', 'Username', 'Profile', 'Privileged', 'Gap_M1_PRMFA', 'Gap_M2_NoMFA', 'Gap_M3_ReportStepUp']];
    for (const id of ids) {
      const u = userMap.get(id) || { id, name: '(unknown)', username: '', profile: '' };
      rows.push([u.id, u.name, u.username, u.profile, privUsers.has(id) ? 'Y' : '', inM1.has(id) ? 'Y' : '', inM2.has(id) ? 'Y' : '', inM3.has(id) ? 'Y' : '']);
    }
    csvPath = val('--export-csv', '') || `mandate-gaps-${ORG}-${report.scannedAt.slice(0, 10)}.csv`;
    writeFileSync(csvPath, rows.map((r) => r.map(csvCell).join(',')).join('\n') + '\n');
    report.csvPath = csvPath;
    report.csvRows = rows.length - 1;
  }

  /* ── Output ── */
  if (JSON_OUT) { console.log(JSON.stringify(report, null, 2)); return report.mandates.some((m) => m.verdict === 'GAP') ? 2 : 0; }

  const vColor = { READY: C.grn, GAP: C.red, REVIEW: C.yel, DEFAULT_WILL_APPLY: C.yel, INFORM: C.cyn, MANUAL: C.dim };
  console.log(`\n${C.b}Salesforce Security Mandate Readiness${C.x}  ${C.dim}(${ORG} · ${report.scannedAt.slice(0, 10)})${C.x}\n`);
  let gaps = 0;
  for (const m of report.mandates) {
    const col = vColor[m.verdict] || C.x;
    console.log(`${col}${m.verdict.padEnd(18)}${C.x} ${C.b}[M${m.id}] ${m.title}${C.x}  ${C.dim}${m.enforce} · ${m.status}${C.x}`);
    console.log(`   ${m.detail}`);
    const mk = Object.entries(m.metrics || {}).filter(([, v]) => v !== null && !(Array.isArray(v) && !v.length));
    if (mk.length) console.log(`   ${C.dim}${mk.map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('/') : v}`).join('  ')}${C.x}`);
    console.log('');
    if (m.verdict === 'GAP') gaps++;
  }
  if (csvPath) console.log(`${C.cyn}per-user remediation list →${C.x} ${csvPath} ${C.dim}(${report.csvRows} users)${C.x}\n`);
  console.log(`${C.b}Summary:${C.x} ${gaps} mandate(s) with a measurable GAP. ${C.dim}MANUAL/INFORM items require config verification not visible to SOQL.${C.x}`);
  return gaps > 0 ? 2 : 0;
}

// Auto-run when executed directly (but not when imported by the unified CLI).
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  runReadiness().then((code) => process.exit(code)).catch((e) => { console.error(e.message); process.exit(1); });
}
