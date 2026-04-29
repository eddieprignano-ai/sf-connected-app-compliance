# Contributing

Thanks for your interest. This is a single-file tool with no runtime
dependencies, so contributing is mechanically simple.

## Filing issues

Useful issue templates:

- **False positive on a publisher attribution** — include the app name,
  what the tool reported, what the actual publisher is, and how you know
  (e.g., AppExchange listing URL, Setup page screenshot with redactions).
- **False negative on a break-condition** — include the app config (with any
  sensitive values redacted), the rule that should have fired, and ideally
  the SOQL query / metadata field you'd point at.
- **A new compliance rule worth adding** — link the Salesforce Release Update
  or hardening doc, and propose how to detect compliance from queryable data
  or metadata.
- **A queryable field for ECA refresh-token rotation** — currently the tool
  marks this rule SKIPPED for ECAs because no field exposes it. If a future
  API version adds one, please file an issue with the field name + sample
  query.

## Pull requests

The tool is `connected-app-compliance.mjs` — single file, ESM, vanilla Node.
No build step, no transpiler.

To test a change:

```bash
# Authenticate against any Salesforce sandbox you have access to
sf org login web --alias mysandbox

# Run against it
node connected-app-compliance.mjs --org mysandbox --check-metadata
```

For PRs that add or change compliance rules:

- Update `RULES` (the catalog) with `label`, `severity`, and `why`.
- Update `BREAK_CONDITION_RULES` if the rule's failure means OAuth actually breaks.
- Update `evaluateLegacyApp` and/or `evaluateECA` with the rule logic. Use
  `pass: null` for "rule does not apply" — this prevents false-FAILs on
  apps that the rule shouldn't gate.
- Update the README's "Compliance rules" table.
- Update CHANGELOG.

For PRs that add a publisher attribution pattern:

- Update `SALESFORCE_NATIVE_PATTERNS` for first-party Salesforce apps. Be
  conservative — incorrect matches here under-credit partner risk.
- Document the source you used to identify the publisher (AppExchange listing,
  Salesforce help doc, etc.) in the PR description.

## Testing philosophy

The original tool was developed against a real production org and verified
finding-by-finding. There's no automated test suite — every claim the tool
makes ("this app will break") is sourced from real metadata or SOQL data, not
heuristic. If you change a rule, please test against at least one real org
(sandbox is fine) and confirm no false-FAILs in the output.

## Code style

- Vanilla ES modules, no transpilation.
- No external runtime dependencies. The Salesforce CLI (`sf`) is the only
  required external binary.
- Output should be human-readable by default, machine-readable on demand
  (`--json`, `--csv`).
- Error states should degrade gracefully — a failed retrieval should produce
  a SKIPPED finding with a clear reason, not a thrown exception.
