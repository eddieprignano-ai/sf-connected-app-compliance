/**
 * Shared helpers for sf-connected-app-compliance and its --readiness companion.
 *
 * Centralizes the things that determine whether a stranger's first run succeeds:
 *   - robust `sf` invocation that surfaces the REAL error (CLI puts JSON errors
 *     on stdout; the actual failure is usually NOT in stderr)
 *   - config / allowlist loading (.sfcompliance.json)
 *   - enforcement-date countdown
 *   - a generic HTML / Markdown scorecard renderer
 *   - preflight object/permission probes (--doctor)
 */

import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';

export const C = { red: '\x1b[31m', yel: '\x1b[33m', grn: '\x1b[32m', cyn: '\x1b[36m', dim: '\x1b[2m', b: '\x1b[1m', x: '\x1b[0m' };

/** Salesforce 2026 mandate production enforcement dates (null = already in effect). */
export const ENFORCEMENT = {
  connectedApp: '2026-05-11', // ISV / ECA mandate
  1: '2026-07-01', 2: '2026-07-20', '2b': '2026-07-20', '2c': '2026-07-01',
  3: '2026-07-01', 4: '2026-07-13', 5: '2026-07-13', 8: null, '6+7': null, '6.mobile': '2026-07-01',
};

export function daysUntil(dateStr, now = new Date()) {
  if (!dateStr) return null;
  const ms = new Date(dateStr + 'T00:00:00Z').getTime() - now.getTime();
  return Math.ceil(ms / 86400000);
}

export function countdownLabel(dateStr, now = new Date()) {
  const d = daysUntil(dateStr, now);
  if (d === null) return 'in effect';
  if (d < 0) return `ENFORCED ${-d}d ago`;
  if (d === 0) return 'ENFORCES TODAY';
  return `${d}d left`;
}

/**
 * A Complierror carries a clean, human-readable message extracted from the
 * Salesforce CLI's stdout JSON (where the real error lives), with stderr noise
 * (update notices, transpile warnings) stripped.
 */
export class CompliError extends Error {}

function cleanStderr(s) {
  return (s || '').toString().split('\n')
    .filter((l) => l.trim() && !/›\s*Warning:/.test(l) && !/auto-transpiled|update available|Existing compiled source/i.test(l))
    .join('\n').trim();
}

/** Pull the real error out of an execSync failure: stdout JSON first, then stderr. */
export function realError(e) {
  const out = (e.stdout || '').toString();
  const i = out.indexOf('{');
  if (i >= 0) {
    try {
      const j = JSON.parse(out.slice(i));
      const msg = j.message || j.error || (Array.isArray(j.result) ? null : null);
      if (msg) return `${j.name ? j.name + ': ' : ''}${msg}`.slice(0, 300);
    } catch { /* fall through */ }
  }
  return cleanStderr(e.stderr) || (e.message || '').slice(0, 300);
}

/** Run an sf CLI command, returning parsed JSON .result; throws CompliError with a clean message. */
export function sfRun(cmd) {
  let raw;
  try {
    raw = execSync(cmd, { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }).toString();
  } catch (e) {
    throw new CompliError(realError(e));
  }
  const i = raw.indexOf('{');
  if (i < 0) throw new CompliError('no JSON in CLI output');
  return JSON.parse(raw.slice(i)).result;
}

export function sfQuery(org, soql, { tooling = false } = {}) {
  const q = soql.replace(/\s+/g, ' ').trim();
  const cmd = `sf data query --query "${q}" --target-org ${org} ${tooling ? '--use-tooling-api' : ''} --json`;
  return sfRun(cmd)?.records ?? [];
}

/** Map common Salesforce errors to a friendly "why this was skipped" reason. */
export function skipReason(msg) {
  const m = (msg || '').toLowerCase();
  if (/not supported|invalid type|sObject type .* is not supported|no such (column|relationship)/i.test(msg)) return 'object/field not available in this org (edition/feature not enabled)';
  if (/insufficient access|not have permission|insufficient_access/.test(m)) return 'insufficient permissions for the running user';
  if (/event monitoring|eventlogfile/.test(m)) return 'requires Event Monitoring license';
  if (/transactionsecuritypolicy|shield/.test(m)) return 'requires Salesforce Shield';
  if (/no active session|expired|please .* login|refresh token/.test(m)) return 'sf CLI session expired — run `sf org login web`';
  return msg;
}

/* ───────────────────────── config / allowlist ───────────────────────── */
export function loadConfig(explicitPath) {
  const path = explicitPath || (existsSync('.sfcompliance.json') ? '.sfcompliance.json' : null);
  if (!path) return {};
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (e) { console.error(`${C.yel}warning:${C.x} could not read config ${path}: ${e.message}`); return {}; }
}

/* ───────────────────────── doctor / preflight ───────────────────────── */
export function doctor(org) {
  const probes = [
    { label: 'sf CLI installed', test: () => { execSync('sf --version', { stdio: ['ignore', 'pipe', 'pipe'] }); return 'ok'; } },
    { label: `org "${org}" reachable`, test: () => { const r = sfRun(`sf org display --target-org ${org} --json`); return r?.username || 'ok'; } },
    { label: 'ConnectedApplication (Tooling)', test: () => { sfQuery(org, 'SELECT Id FROM ConnectedApplication LIMIT 1', { tooling: true }); return 'queryable'; } },
    { label: 'TwoFactorMethodsInfo (MFA checks)', test: () => { sfQuery(org, 'SELECT Id FROM TwoFactorMethodsInfo LIMIT 1'); return 'queryable'; } },
    { label: 'LoginHistory AMR/ACR (IdP signal)', test: () => { sfQuery(org, 'SELECT AuthMethodReference FROM LoginHistory LIMIT 1'); return 'queryable'; } },
    { label: 'EventLogFile (export footprint)', test: () => { sfQuery(org, "SELECT Id FROM EventLogFile WHERE EventType='ReportExport' LIMIT 1"); return 'queryable (Event Monitoring on)'; } },
    { label: 'TransactionSecurityPolicy (Shield)', test: () => { sfQuery(org, 'SELECT Id FROM TransactionSecurityPolicy LIMIT 1', { tooling: true }); return 'queryable (Shield on)'; } },
    { label: 'OrgWideEmailAddress (email domain)', test: () => { sfQuery(org, 'SELECT Id FROM OrgWideEmailAddress LIMIT 1'); return 'queryable'; } },
  ];
  const results = [];
  for (const p of probes) {
    try { results.push({ label: p.label, ok: true, note: p.test() }); }
    catch (e) { results.push({ label: p.label, ok: false, note: skipReason(e.message) }); }
  }
  return results;
}

export function printDoctor(org) {
  const results = doctor(org);
  console.log(`\n${C.b}Preflight — org: ${C.cyn}${org}${C.x}\n`);
  for (const r of results) console.log(`  ${r.ok ? C.grn + '✓' : C.red + '✗'}${C.x} ${r.label.padEnd(38)} ${C.dim}${r.note}${C.x}`);
  const fails = results.filter((r) => !r.ok).length;
  console.log(`\n${C.b}${fails === 0 ? C.grn + 'All preflight checks passed.' : C.yel + fails + ' check(s) unavailable — related findings will be SKIPPED with a reason.'}${C.x}\n`);
  return results;
}

/* ───────────────────────── report renderers ─────────────────────────
 * Both tools normalize into: { title, org, generatedAt, groups: [{ heading,
 * rows: [{ status, label, detail, meta, enforce }] }] }
 */
const STATUS_RGB = { READY: '#1a7f37', COMPLIANT: '#1a7f37', GAP: '#cf222e', WILL_BREAK: '#cf222e', NON_COMPLIANT: '#cf222e', NEEDS_REVIEW: '#9a6700', REVIEW: '#9a6700', DEFAULT_WILL_APPLY: '#9a6700', INFORM: '#0969da', MANUAL: '#57606a', SKIPPED: '#57606a', UNKNOWN: '#57606a' };

export function renderMarkdown(report) {
  const lines = [`# ${report.title}`, '', `**Org:** ${report.org}  ·  **Generated:** ${report.generatedAt}`, ''];
  for (const g of report.groups) {
    lines.push(`## ${g.heading}`, '', '| Status | Item | Deadline | Detail |', '|---|---|---|---|');
    for (const r of g.rows) lines.push(`| ${r.status} | ${r.label} | ${r.enforce || ''} | ${(r.detail || '').replace(/\|/g, '\\|').replace(/\n/g, ' ')} |`);
    lines.push('');
  }
  return lines.join('\n') + '\n';
}

export function renderHtml(report) {
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const pill = (s) => `<span style="background:${STATUS_RGB[s] || '#57606a'};color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap">${esc(s)}</span>`;
  const groups = report.groups.map((g) => `
    <h2>${esc(g.heading)}</h2>
    <table>
      <thead><tr><th>Status</th><th>Item</th><th>Deadline</th><th>Detail</th></tr></thead>
      <tbody>${g.rows.map((r) => `<tr><td>${pill(r.status)}</td><td><b>${esc(r.label)}</b>${r.meta ? `<br><span class="meta">${esc(r.meta)}</span>` : ''}</td><td class="dl">${esc(r.enforce || '')}</td><td>${esc(r.detail)}</td></tr>`).join('')}</tbody>
    </table>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(report.title)}</title>
<style>
  body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#1f2328}
  h1{font-size:24px;margin-bottom:4px} h2{font-size:16px;margin-top:28px;border-bottom:1px solid #d0d7de;padding-bottom:6px}
  .sub{color:#57606a;margin-bottom:20px}
  table{border-collapse:collapse;width:100%;margin-top:8px} th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eaeef2;vertical-align:top;font-size:13px}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#57606a} td.dl{white-space:nowrap;color:#57606a} .meta{color:#57606a;font-size:12px}
</style></head><body>
  <h1>${esc(report.title)}</h1>
  <div class="sub">Org: <b>${esc(report.org)}</b> &middot; Generated ${esc(report.generatedAt)}</div>
  ${groups}
  <p class="sub" style="margin-top:28px">Read-only audit. MANUAL/INFORM items require config verification not visible to SOQL. Generated by sf-connected-app-compliance.</p>
</body></html>`;
}
