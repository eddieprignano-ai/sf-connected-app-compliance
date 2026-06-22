import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyIpRelaxation } from '../lib.mjs';

test('ECA string enums classify correctly', () => {
  assert.equal(classifyIpRelaxation('Enforce'), true);
  assert.equal(classifyIpRelaxation('EnforceForRefreshToken'), true);
  assert.equal(classifyIpRelaxation('Relax'), false);
  assert.equal(classifyIpRelaxation('RelaxForRefreshToken'), false);
});

test('legacy numeric picklist still works (back-compat)', () => {
  assert.equal(classifyIpRelaxation('0'), true);
  assert.equal(classifyIpRelaxation(0), true);
  assert.equal(classifyIpRelaxation('3'), true);
  assert.equal(classifyIpRelaxation('1'), false);
  assert.equal(classifyIpRelaxation('2'), false);
});

test('unset / unrecognized → null (never guess)', () => {
  assert.equal(classifyIpRelaxation(null), null);
  assert.equal(classifyIpRelaxation(undefined), null);
  assert.equal(classifyIpRelaxation(''), null);
  assert.equal(classifyIpRelaxation('SomethingNew'), null);
});

test('regression: "Enforce" must NOT be reported as relaxed (2026-06-22 bug)', () => {
  // Old logic `ip === "0" || ip === "3"` failed on the real string "Enforce",
  // so every ECA (which returns "Enforce") was false-flagged as relaxed.
  assert.equal(classifyIpRelaxation('Enforce'), true, '"Enforce" string must classify as enforced');
});
