#!/usr/bin/env node
/**
 * sf-security-mandate-readiness
 *
 * Companion to connected-app-compliance.mjs. Where that tool covers the
 * Connected App / ECA OAuth hardening mandate, this assesses the OTHER seven
 * Salesforce June–July 2026 security mandates measurable from SOQL/metadata.
 * Runtime/client-side controls are emitted as MANUAL with the Setup location —
 * never fabricated. Read-only. Requires an authenticated `sf` CLI session.
 *
 * Mandates: 1 PRMFA admins · 2 MFA all users (+2b exemption holders, +2c the
 * live SSO AMR/ACR signal) · 3 report step-up · 4 anomalous-export footprint ·
 * 5 ReportEvent TSP · 8 email-domain · 6/7 + mobile MANUAL.
 *
 * Usage:
 *   node mandate-readiness.mjs --org <alias>[,<alias2>] [options]
 *     --doctor            Preflight only: what's queryable in this org
 *     --export-csv [file] Per-user remediation list (gitignored by default)
 *     --html [file]       Executive HTML scorecard
 *     --md [file]         Markdown scorecard
 *     --raw               Dump the raw AMR/ACR + method-enrollment signal
 *     --config <file>     .sfcompliance.json (allowlists, AMR token overrides)
 *     --export-days N      ReportExport window (default 30)
 *     --idp-days N         AMR/ACR LoginHistory window (default 7)
 *     --json              Machine-readable output
 */

import { writeFileSync } from 'fs';
import { pathToFileURL } from 'url';
import { C, ENFORCEMENT, countdownLabel, sfQuery, skipReason, loadConfig, renderHtml, renderMarkdown, printDoctor } from './lib.mjs';

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const val = (n, d) => { const i = args.indexOf(n); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : d; };

const PRIV_PERMS = ['PermissionsModifyAllData', 'PermissionsViewAllData', 'PermissionsCustomizeApplication', 'PermissionsAuthorApex'];
const INTERACTIVE_LOGIN_TYPES = ['Application', 'SAML Idp Initiated SSO', 'SAML Sfdc Initiated SSO', 'Username-Password', 'Remote Access Client', 'The UI'];
const DEFAULT_AMR_PR = ['hwk', 'fido', 'x509', 'passkey', 'webauthn', 'u2f', 'phr', 'phrh', 'swk'];
const DEFAULT_AMR_STRONG = ['mfa', 'otp', 'sms', 'tel', 'rsa', 'kba', 'mca', 'totp', 'sfa', 'push'];

const csvCell = (v) => { const s = v == null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

function makeClassifiers(cfg) {
  const PR = (cfg.amrPhishingResistant || DEFAULT_AMR_PR).map((s) => s.toLowerCase());
  const STRONG = (cfg.amrStrong || DEFAULT_AMR_STRONG).map((s) => s.toLowerCase());
  return {
    amr: (amr) => { if (!amr) return 'none'; const s = String(amr).toLowerCase(); if (PR.some((t) => s.includes(t))) return 'phishing-resistant'; if (STRONG.some((t) => s.includes(t))) return 'strong'; return 'weak'; },
    acr: (acr) => { if (!acr) return 'none'; const s = String(acr).toLowerCase(); if (/x509|smartcard|fido|webauthn/.test(s)) return 'phishing-resistant'; if (/passwordprotectedtransport|unspecified|:password\b|kerberos|previous-session/.test(s)) return 'weak'; if (/mobiletwofactor|timesynctoken|otp|mfa|hardware|telephony/.test(s)) return 'strong'; return 'unclassified'; },
  };
}

/** Run a query, returning {ok,data} or {ok:false,reason} — never throws. */
function tryQ(fn, jsonOut) {
  try { return { ok: true, data: fn() }; }
  catch (e) { const reason = skipReason(e.message); if (!jsonOut) console.error(`${C.dim}  (skipped: ${reason})${C.x}`); return { ok: false, reason }; }
}

/** Assess one org. Returns { org, mandates, gaps:{m1,m2,m3}, userMap, raw }. */
function assessOrg(org, opts) {
  const { JSON_OUT, EXPORT_DAYS, IDP_DAYS, cfg, cls } = opts;
  const q = (o) => sfQuery(org, o.q, o);
  const allow = new Set((cfg.allowlistUsers || []).map((s) => s.toLowerCase()));
  if (!JSON_OUT) console.error(`${C.dim}assessing — org: ${C.cyn}${org}${C.x}`);

  const mandates = [];
  const skip = (id, title, reason, qs) => mandates.push({ id, title, enforce: ENFORCEMENT[id], status: 'SKIPPED', verdict: 'SKIPPED', metrics: {}, detail: `Not assessed: ${reason}.`, checklistQ: qs });

  /* Users + permission sets */
  const usersR = tryQ(() => q({ q: `SELECT Id, Name, Username, Profile.Name FROM User WHERE IsActive=true AND UserType='Standard'` }), JSON_OUT);
  const usersRaw = usersR.ok ? usersR.data : [];
  const userMap = new Map(usersRaw.map((u) => [u.Id, { id: u.Id, name: u.Name, username: u.Username, profile: u.Profile?.Name || '' }]));
  const notAllowed = (id) => { const u = userMap.get(id); return !(u && allow.has((u.username || '').toLowerCase())); };
  const allStandard = new Set(userMap.keys());

  const privR = tryQ(() => new Set(q({ q: `SELECT AssigneeId FROM PermissionSetAssignment WHERE (${PRIV_PERMS.map((p) => `PermissionSet.${p}=true`).join(' OR ')}) AND Assignee.IsActive=true AND Assignee.UserType='Standard'` }).map((r) => r.AssigneeId)), JSON_OUT);
  const reportR = tryQ(() => new Set(q({ q: `SELECT AssigneeId FROM PermissionSetAssignment WHERE (PermissionSet.PermissionsRunReports=true OR PermissionSet.PermissionsExportReport=true) AND Assignee.IsActive=true AND Assignee.UserType='Standard'` }).map((r) => r.AssigneeId)), JSON_OUT);
  const privUsers = privR.ok ? privR.data : new Set();
  const reportUsers = reportR.ok ? reportR.data : new Set();

  /* MFA method enrollment */
  const prR = tryQ(() => new Set(q({ q: `SELECT UserId FROM TwoFactorMethodsInfo WHERE HasU2F=true OR HasSecurityKey=true OR HasBuiltInAuthenticator=true` }).map((r) => r.UserId)), JSON_OUT);
  const anyR = tryQ(() => new Set(q({ q: `SELECT UserId FROM TwoFactorMethodsInfo WHERE HasU2F=true OR HasSecurityKey=true OR HasBuiltInAuthenticator=true OR HasSalesforceAuthenticator=true OR HasTotp=true OR HasUserVerifiedMobileNumber=true OR HasUserVerifiedEmailAddress=true` }).map((r) => r.UserId)), JSON_OUT);
  const prMethodUsers = prR.ok ? prR.data : new Set();
  const anyMethodUsers = anyR.ok ? anyR.data : new Set();

  /* Interactive vs API split (which privileged users actually log in via UI) */
  const privIds = [...privUsers];
  let interactiveUsers = null;
  if (privIds.length) {
    const inClause = privIds.map((id) => `'${id}'`).join(',');
    const typeClause = INTERACTIVE_LOGIN_TYPES.map((t) => `LoginType='${t}'`).join(' OR ');
    const intR = tryQ(() => new Set(q({ q: `SELECT UserId FROM LoginHistory WHERE LoginTime=LAST_N_DAYS:90 AND UserId IN (${inClause}) AND (${typeClause})` }).map((r) => r.UserId)), JSON_OUT);
    if (intR.ok) interactiveUsers = intR.data;
  }

  /* ── M1: PRMFA admins ── */
  if (!privR.ok) skip(1, 'Phishing-Resistant MFA for Admins', privR.reason, ['Q1', 'Q6', 'Q7']);
  else if (!prR.ok) skip(1, 'Phishing-Resistant MFA for Admins', prR.reason, ['Q1', 'Q6', 'Q7']);
  else {
    const gapAll = privIds.filter((u) => !prMethodUsers.has(u) && notAllowed(u));
    const interactiveGap = interactiveUsers ? gapAll.filter((u) => interactiveUsers.has(u)) : null;
    const apiGap = interactiveUsers ? gapAll.filter((u) => !interactiveUsers.has(u)) : null;
    mandates.push({
      id: 1, title: 'Phishing-Resistant MFA for Admins', enforce: ENFORCEMENT[1], status: 'ASSESSABLE',
      metrics: { privilegedUsers: privUsers.size, gap: gapAll.length, interactiveAdminsInGap: interactiveGap == null ? 'n/a' : interactiveGap.length, apiServiceAcctsInGap: apiGap == null ? 'n/a' : apiGap.length },
      verdict: (interactiveGap == null ? gapAll.length : interactiveGap.length) === 0 ? 'READY' : 'GAP',
      detail: interactiveGap == null
        ? `${gapAll.length}/${privUsers.size} privileged active users have NO phishing-resistant method (U2F/passkey/built-in). TOTP & Salesforce Authenticator do NOT qualify; IdP MFA does NOT satisfy this. (Interactive-vs-API split unavailable — LoginHistory not queryable.)`
        : `${interactiveGap.length} INTERACTIVE admins lack a phishing-resistant method — the true Jul-1 deadline. (${apiGap.length} more are API/service accounts that log in via OAuth/JWT, not interactive MFA — likely out of scope; see CSV.) IdP MFA does NOT satisfy this even under SSO.`,
      checklistQ: ['Q1', 'Q6', 'Q7'],
    });
  }

  /* ── M2: MFA all users ── */
  if (!usersR.ok) skip(2, 'MFA for All Internal Users', usersR.reason, ['Q3', 'Q8']);
  else if (!anyR.ok) skip(2, 'MFA for All Internal Users', anyR.reason, ['Q3', 'Q8']);
  else {
    const gap = [...allStandard].filter((u) => !anyMethodUsers.has(u) && notAllowed(u));
    mandates.push({
      id: 2, title: 'MFA for All Internal Users', enforce: ENFORCEMENT[2], status: 'ASSESSABLE',
      metrics: { activeInternalUsers: allStandard.size, withAnyMethodRegistered: anyMethodUsers.size, notEnrolled: gap.length },
      verdict: gap.length === 0 ? 'READY' : 'GAP',
      detail: `${gap.length} of ${allStandard.size} active internal users have no Salesforce-registered method. SSO users MAY pass via IdP AMR/ACR — but see M2c for whether the signal is actually strong. Front-line/no-smartphone users are highest lockout risk.`,
      checklistQ: ['Q3', 'Q8'],
    });
  }

  /* ── M2c: SSO IdP AMR/ACR signal ── */
  const amrR = tryQ(() => q({ q: `SELECT AuthMethodReference, COUNT(Id) c FROM LoginHistory WHERE LoginTime=LAST_N_DAYS:${IDP_DAYS} GROUP BY AuthMethodReference ORDER BY COUNT(Id) DESC` }), JSON_OUT);
  if (!amrR.ok) skip('2c', 'SSO IdP MFA Signal (AMR/ACR)', amrR.reason, ['Q2', 'Q6']);
  else {
    const acrSample = tryQ(() => q({ q: `SELECT AuthContextClassRef FROM LoginHistory WHERE LoginTime=LAST_N_DAYS:${IDP_DAYS} AND (LoginType='SAML Idp Initiated SSO' OR LoginType='SAML Sfdc Initiated SSO') AND AuthContextClassRef!=null LIMIT 1000` }), JSON_OUT);
    const ssoCount = tryQ(() => q({ q: `SELECT COUNT(Id) c FROM LoginHistory WHERE LoginTime=LAST_N_DAYS:${IDP_DAYS} AND (LoginType='SAML Idp Initiated SSO' OR LoginType='SAML Sfdc Initiated SSO')` }), JSON_OUT);
    let amrPR = 0, amrStrong = 0, amrTotal = 0;
    for (const r of amrR.data) { const n = Number(r.c) || 0; amrTotal += n; const t = cls.amr(r.AuthMethodReference); if (t === 'phishing-resistant') amrPR += n; else if (t === 'strong') amrStrong += n; }
    const acrRows = acrSample.ok ? acrSample.data : [];
    const acrTally = {};
    for (const r of acrRows) { const t = cls.acr(r.AuthContextClassRef); acrTally[t] = (acrTally[t] || 0) + 1; }
    const acrDominant = Object.entries(acrTally).sort((a, b) => b[1] - a[1])[0]?.[0] || 'none';
    const dominantAcrValue = [...new Set(acrRows.map((r) => r.AuthContextClassRef))].slice(0, 3);
    const tier = (amrPR > 0 || acrDominant === 'phishing-resistant') ? 'phishing-resistant' : (amrStrong > 0 || acrDominant === 'strong') ? 'strong' : 'weak';
    mandates.push({
      id: '2c', title: 'SSO IdP MFA Signal (AMR/ACR)', enforce: ENFORCEMENT['2c'], status: 'ASSESSABLE',
      metrics: { ssoLoginsWindow: ssoCount.ok ? (ssoCount.data[0]?.c ?? 0) : 'n/a', amrStrongOrPRLogins: amrPR + amrStrong, amrTotalLogins: amrTotal, dominantAcrTier: acrDominant, dominantAcrValue, classifiedTier: tier },
      verdict: tier === 'phishing-resistant' ? 'READY' : tier === 'strong' ? 'REVIEW' : 'GAP',
      detail: tier === 'weak'
        ? `IdP sends a WEAK signal (AMR ${amrPR + amrStrong === 0 ? 'absent/none' : 'mostly weak'}; dominant ACR "${dominantAcrValue[0] || 'n/a'}"). Not MFA under SF's 3-tier model → SSO will NOT satisfy M2 (every internal user challenged) and cannot satisfy M1/M3. ACTION: configure the IdP (Okta: FIDO2/FastPass + AMR attribute / strong AuthnContextClassRef; Entra: AuthnContextClassRef gap — request deferral + native keys), test in sandbox, re-run this check.`
        : tier === 'strong'
        ? `IdP sends a STRONG (non-PR) signal — satisfies M2, but NOT M1/M3 (need phishing-resistant or native method). Upgrade privileged users to FIDO2/passkey/key.`
        : `IdP sends a phishing-resistant signal on ${amrPR} logins. Confirm coverage spans the privileged population for M1.`,
      checklistQ: ['Q2', 'Q6'],
    });
  }

  /* ── M2b: bypass-MFA exemption holders ── */
  const waiveR = tryQ(() => q({ q: `SELECT COUNT(Id) c FROM PermissionSetAssignment WHERE PermissionSet.PermissionsBypassMFAForUiLogins=true AND Assignee.IsActive=true` })[0]?.c ?? 0, JSON_OUT);
  if (waiveR.ok) mandates.push({ id: '2b', title: 'MFA Exemption Holders (Bypass MFA for UI Logins)', enforce: ENFORCEMENT['2b'], status: 'ASSESSABLE', metrics: { bypassMfaAssignments: waiveR.data }, verdict: waiveR.data === 0 ? 'READY' : 'REVIEW', detail: `${waiveR.data} active "Bypass MFA for UI Logins" assignment(s). Each must be justified (automation users only) and will require a Salesforce Case to retain post-enforcement.`, checklistQ: ['Q5'] });

  /* ── M3: report step-up ── */
  if (!reportR.ok) skip(3, 'Step-Up Auth on Report Actions', reportR.reason, ['Q15', 'Q16']);
  else if (!anyR.ok) skip(3, 'Step-Up Auth on Report Actions', anyR.reason, ['Q15', 'Q16']);
  else {
    const gap = [...reportUsers].filter((u) => !anyMethodUsers.has(u) && notAllowed(u));
    mandates.push({ id: 3, title: 'Step-Up Auth on Report Actions', enforce: ENFORCEMENT[3], status: 'PARTIAL', metrics: { reportRunningUsers: reportUsers.size, withoutAnyNativeMethod: gap.length }, verdict: gap.length === 0 ? 'READY' : 'GAP', detail: `${gap.length}/${reportUsers.size} report-running users have no Salesforce-native method. Step-up does NOT accept Enterprise-IdP MFA; email step-up auto-enrolls at first challenge (Jun 11 update), but no valid email = lockout.`, checklistQ: ['Q15', 'Q16'] });
  }

  /* ── M5: ReportEvent TSP ── */
  const tspR = tryQ(() => q({ q: `SELECT DeveloperName, EventName, State FROM TransactionSecurityPolicy WHERE EventName='ReportEvent'`, tooling: true }), JSON_OUT);
  if (!tspR.ok) skip(5, 'Transaction Security Policy for Report Exports', tspR.reason, ['Q18', 'Q20']);
  else mandates.push({ id: 5, title: 'Transaction Security Policy for Report Exports', enforce: ENFORCEMENT[5], status: 'ASSESSABLE', metrics: { qualifyingReportEventTSPs: tspR.data.length }, verdict: tspR.data.length > 0 ? 'READY' : 'DEFAULT_WILL_APPLY', detail: tspR.data.length > 0 ? `${tspR.data.length} ReportEvent TSP(s) configured (${tspR.data.map((t) => t.DeveloperName + ':' + t.State).join(', ')}).` : `No qualifying ReportEvent TSP — Salesforce auto-adds a DEFAULT policy prompting step-up at >10,000-row exports. Configure your own to control thresholds/exemptions.`, checklistQ: ['Q18', 'Q20'] });

  /* ── M4: anomalous export footprint ── */
  const elfR = tryQ(() => q({ q: `SELECT COUNT(Id) c FROM EventLogFile WHERE EventType='ReportExport' AND LogDate=LAST_N_DAYS:${EXPORT_DAYS}` })[0]?.c ?? 0, JSON_OUT);
  mandates.push({ id: 4, title: 'Step-Up Auth on Anomalous Report Exports', enforce: ENFORCEMENT[4], status: 'FOOTPRINT-ONLY', metrics: { reportExportLogFiles: elfR.ok ? elfR.data : `n/a (${elfR.reason})` }, verdict: 'INFORM', detail: `ML-driven; no admin-visible config, so readiness cannot be scored. ${elfR.ok ? `Footprint: ${elfR.data} ReportExport log(s) in ${EXPORT_DAYS}d — scripted/scheduled exports may trip the model with no warning. Review headless/integration export jobs.` : `Export footprint unavailable: ${elfR.reason}.`}`, checklistQ: ['Q17', 'Q18'] });

  /* ── M8: email domain verification ── */
  const oweaR = tryQ(() => q({ q: `SELECT Address, IsVerified FROM OrgWideEmailAddress` }), JSON_OUT);
  if (!oweaR.ok) skip(8, 'Email Domain Verification', oweaR.reason, ['Q13', 'Q14']);
  else {
    const dkimR = tryQ(() => q({ q: `SELECT Domain, IsActive FROM EmailDomainKey` }), JSON_OUT);
    const unverified = oweaR.data.filter((a) => a.IsVerified === false);
    const activeDkim = dkimR.ok ? [...new Set(dkimR.data.filter((d) => d.IsActive).map((d) => d.Domain))] : [];
    mandates.push({ id: 8, title: 'Email Domain Verification', enforce: ENFORCEMENT[8], status: 'ASSESSABLE', metrics: { orgWideAddresses: oweaR.data.length, unverifiedAddresses: unverified.length, activeDkimDomains: activeDkim }, verdict: unverified.length === 0 ? 'READY' : 'GAP', detail: unverified.length === 0 ? `All ${oweaR.data.length} org-wide addresses verified; active DKIM: ${activeDkim.join(', ') || 'none'}. Does not cover every flow/Apex sending domain — verify domain allowlist separately incl. sandboxes.` : `${unverified.length} unverified: ${unverified.map((a) => a.Address).join(', ')}. Unverified senders will be blocked.`, checklistQ: ['Q13', 'Q14'] });
  }

  /* ── M6/M7 + Mobile: MANUAL ── */
  mandates.push({ id: '6+7', title: 'Anonymizing-IP Block + Login-Anomaly Containment', enforce: ENFORCEMENT['6+7'], status: 'MANUAL', metrics: {}, verdict: 'MANUAL', detail: `Runtime ML — not scoreable from SOQL. MANUAL: (a) Setup → Company Information → set a Security Contact distribution list [Q10]; (b) name an owner + unfreeze/reset runbook [Q9]; (c) request Support exemptions for service users on VPN/cloud IPs [Q11]; (d) reconcile with Shield Threat Detection [Q12].`, checklistQ: ['Q9', 'Q10', 'Q11', 'Q12'] });
  mandates.push({ id: '6.mobile', title: 'Mobile SDK 13.2.1 cutover', enforce: ENFORCEMENT['6.mobile'], status: 'MANUAL', metrics: {}, verdict: 'MANUAL', detail: `Client-side; not queryable. MANUAL: confirm in-house apps on Salesforce Mobile SDK are ≥13.2.1; verify InTune/Edge auth for Salesforce Mobile on iOS [Q24, Q25].`, checklistQ: ['Q24', 'Q25'] });

  // Gap user-id lists for CSV.
  const gaps = {
    m1: privR.ok && prR.ok ? privIds.filter((u) => !prMethodUsers.has(u) && notAllowed(u)) : [],
    m2: usersR.ok && anyR.ok ? [...allStandard].filter((u) => !anyMethodUsers.has(u) && notAllowed(u)) : [],
    m3: reportR.ok && anyR.ok ? [...reportUsers].filter((u) => !anyMethodUsers.has(u) && notAllowed(u)) : [],
  };
  const raw = { amrDist: amrR.ok ? amrR.data : null };
  return { org, scannedAt: new Date().toISOString(), mandates, gaps, userMap, privUsers, interactiveUsers, raw };
}

/* ───────────────────────────── output ───────────────────────────── */
function toGenericReport(rep) {
  const rows = rep.mandates.map((m) => ({
    status: m.verdict,
    label: `[M${m.id}] ${m.title}`,
    enforce: m.enforce ? `${m.enforce} (${countdownLabel(m.enforce)})` : 'in effect',
    detail: m.detail,
    meta: Object.entries(m.metrics || {}).filter(([, v]) => v != null && !(Array.isArray(v) && !v.length)).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('/') : v}`).join('  '),
  }));
  return { title: 'Salesforce Security Mandate Readiness', org: rep.org, generatedAt: rep.scannedAt.slice(0, 19).replace('T', ' '), groups: [{ heading: 'Mandates', rows }] };
}

function printConsole(rep) {
  const vColor = { READY: C.grn, GAP: C.red, REVIEW: C.yel, DEFAULT_WILL_APPLY: C.yel, INFORM: C.cyn, MANUAL: C.dim, SKIPPED: C.dim };
  console.log(`\n${C.b}Salesforce Security Mandate Readiness${C.x}  ${C.dim}(${rep.org} · ${rep.scannedAt.slice(0, 10)})${C.x}\n`);
  let gaps = 0;
  for (const m of rep.mandates) {
    const col = vColor[m.verdict] || C.x;
    const cd = m.enforce ? ` · ${countdownLabel(m.enforce)}` : ' · in effect';
    console.log(`${col}${m.verdict.padEnd(18)}${C.x} ${C.b}[M${m.id}] ${m.title}${C.x}  ${C.dim}${m.enforce || 'in effect'}${cd}${C.x}`);
    console.log(`   ${m.detail}`);
    const mk = Object.entries(m.metrics || {}).filter(([, v]) => v != null && !(Array.isArray(v) && !v.length));
    if (mk.length) console.log(`   ${C.dim}${mk.map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('/') : v}`).join('  ')}${C.x}`);
    console.log('');
    if (m.verdict === 'GAP') gaps++;
  }
  return gaps;
}

function writeCsv(rep, file) {
  const inM1 = new Set(rep.gaps.m1), inM2 = new Set(rep.gaps.m2), inM3 = new Set(rep.gaps.m3);
  const ids = new Set([...rep.gaps.m1, ...rep.gaps.m2, ...rep.gaps.m3]);
  const rows = [['User Id', 'Name', 'Username', 'Profile', 'Privileged', 'Interactive', 'Gap_M1_PRMFA', 'Gap_M2_NoMFA', 'Gap_M3_ReportStepUp']];
  for (const id of ids) {
    const u = rep.userMap.get(id) || { id, name: '(unknown)', username: '', profile: '' };
    const interactive = rep.interactiveUsers ? (rep.interactiveUsers.has(id) ? 'Y' : 'N') : '?';
    rows.push([u.id, u.name, u.username, u.profile, rep.privUsers.has(id) ? 'Y' : '', interactive, inM1.has(id) ? 'Y' : '', inM2.has(id) ? 'Y' : '', inM3.has(id) ? 'Y' : '']);
  }
  const path = file || `mandate-gaps-${rep.org}-${rep.scannedAt.slice(0, 10)}.csv`;
  writeFileSync(path, rows.map((r) => r.map(csvCell).join(',')).join('\n') + '\n');
  return { path, count: rows.length - 1 };
}

function printRaw(rep) {
  console.log(`\n${C.b}RAW IdP signal — ${rep.org}${C.x}`);
  console.log(`${C.dim}AMR distribution (last window):${C.x}`);
  for (const r of (rep.raw.amrDist || [])) console.log(`  ${String(r.c).padStart(9)}  AMR=${JSON.stringify(r.AuthMethodReference)}`);
}

export async function runReadiness() {
  const orgArg = val('--org', process.env.DEFAULT_SALESFORCE_ORG || '');
  const orgs = orgArg.split(',').map((s) => s.trim()).filter(Boolean);
  const JSON_OUT = flag('--json');
  if (flag('-h') || flag('--help')) {
    console.log(`Usage: mandate-readiness.mjs --org <alias>[,<alias2>] [--doctor] [--export-csv [file]] [--html [file]] [--md [file]] [--raw] [--config <file>] [--export-days N] [--idp-days N] [--json]`);
    return 0;
  }
  if (!orgs.length) { console.error('error: pass --org <alias> (or set DEFAULT_SALESFORCE_ORG)'); return 1; }

  if (flag('--doctor')) { for (const o of orgs) printDoctor(o); return 0; }

  const cfg = loadConfig(val('--config', null));
  const opts = { JSON_OUT, EXPORT_DAYS: parseInt(val('--export-days', '30'), 10), IDP_DAYS: parseInt(val('--idp-days', '7'), 10), cfg, cls: makeClassifiers(cfg) };

  const reports = orgs.map((o) => assessOrg(o, opts));

  // Multi-org diff
  if (reports.length > 1 && !JSON_OUT) {
    console.log(`\n${C.b}Multi-org verdict diff${C.x}\n`);
    const ids = reports[0].mandates.map((m) => m.id);
    const header = ['Mandate'.padEnd(34), ...reports.map((r) => r.org.padEnd(14))].join(' ');
    console.log(C.dim + header + C.x);
    for (const id of ids) {
      const title = reports[0].mandates.find((m) => m.id === id)?.title || '';
      const cells = reports.map((r) => { const v = r.mandates.find((m) => m.id === id)?.verdict || '-'; const col = v === 'GAP' ? C.red : v === 'READY' ? C.grn : v === 'REVIEW' || v === 'DEFAULT_WILL_APPLY' ? C.yel : C.dim; return col + v.padEnd(14) + C.x; });
      console.log(`[M${id}] ${title}`.slice(0, 34).padEnd(34) + ' ' + cells.join(' '));
    }
    console.log('');
  }

  if (JSON_OUT) { console.log(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2)); return reports.some((r) => r.mandates.some((m) => m.verdict === 'GAP')) ? 2 : 0; }

  let totalGaps = 0;
  for (const rep of reports) {
    totalGaps += printConsole(rep);
    if (flag('--raw')) printRaw(rep);
    if (flag('--export-csv')) { const { path, count } = writeCsv(rep, val('--export-csv', '')); console.log(`${C.cyn}per-user remediation list →${C.x} ${path} ${C.dim}(${count} users)${C.x}`); }
    if (flag('--html')) { const f = val('--html', '') || `mandate-readiness-${rep.org}-${rep.scannedAt.slice(0, 10)}.html`; writeFileSync(f, renderHtml(toGenericReport(rep))); console.log(`${C.cyn}HTML scorecard →${C.x} ${f}`); }
    if (flag('--md')) { const f = val('--md', '') || `mandate-readiness-${rep.org}-${rep.scannedAt.slice(0, 10)}.md`; writeFileSync(f, renderMarkdown(toGenericReport(rep))); console.log(`${C.cyn}Markdown scorecard →${C.x} ${f}`); }
  }
  console.log(`\n${C.b}Summary:${C.x} ${totalGaps} measurable GAP(s) across ${reports.length} org(s). ${C.dim}MANUAL/INFORM/SKIPPED need config or license verification.${C.x}`);
  return totalGaps > 0 ? 2 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  runReadiness().then((code) => process.exit(code)).catch((e) => { console.error(e.message); process.exit(1); });
}
