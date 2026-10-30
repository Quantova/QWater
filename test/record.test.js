// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');
const key = () => Q.generateKey();
const mk = (k, h) => Q.allocate({ key: k, source: 'River Aqua Intake 3', volumeM3: 2000000, basin: 'rhine', jurisdiction: 'de', holder: Q.keyId(h), authorityLabel: 'Water Authority' });

test('an allocated right is a well formed signed record of the authority', () => {
  const a = key(); const h = key(); const g = mk(a, h);
  assert.strictEqual(g.format, 'qwater/1');
  assert.strictEqual(g.type, 'allocate');
  assert.strictEqual(g.signer.id, Q.keyId(a));
  assert.strictEqual(g.statement.holderKeyId, Q.keyId(h));
  assert.strictEqual(g.statement.volumeM3, 2000000);
  assert.match(g.statement.rightId, /^[0-9a-f]{32}$/);
});

test('use transfer revoke chain to the same right', () => {
  const a = key(); const h = key(); const buyer = key();
  const g = mk(a, h);
  const u = Q.use({ key: h, right: g, period: '2026', volumeM3: 1500000 });
  const moved = Q.transfer({ key: h, right: g, to: Q.keyId(buyer) });
  const end = Q.revoke({ key: a, right: moved, reason: 'drought order' });
  assert.strictEqual(u.statement.rightId, g.statement.rightId);
  assert.strictEqual(u.statement.volumeM3, 1500000);
  assert.strictEqual(moved.statement.toKeyId, Q.keyId(buyer));
  assert.strictEqual(end.statement.reason, 'drought order');
});

test('invalid inputs are refused before anything is signed', () => {
  const k = key(); const h = key();
  const base = { key: k, source: 'S1', volumeM3: 1, basin: 'rhine', jurisdiction: 'de', holder: Q.keyId(h) };
  assert.throws(() => Q.allocate(Object.assign({}, base, { basin: 'Rhine' })), /basin must be/);
  assert.throws(() => Q.allocate(Object.assign({}, base, { volumeM3: 0 })), /volumeM3 must be a whole number/);
  assert.throws(() => Q.allocate(Object.assign({}, base, { jurisdiction: 'DE' })), /jurisdiction must be/);
  assert.throws(() => Q.allocate(Object.assign({}, base, { zzz: 1 })), /is not an option of allocate/);
});

test('a well formed record verifies and a type mismatch or tamper is invalid', async () => {
  const a = key(); const h = key(); const g = mk(a, h);
  const OPTS = { network: 'testnet', requireAnchor: false, strict: false };
  const ok = await Q.verify(g, Object.assign({ type: 'allocate' }, OPTS));
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.rightId, g.statement.rightId);
  assert.strictEqual((await Q.verify(g, Object.assign({ type: 'transfer' }, OPTS))).status, 'invalid');
  const f = JSON.parse(JSON.stringify(g)); f.statement.volumeM3 = 1;
  assert.strictEqual((await Q.verify(f, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
});

test('the prior link binds and the kind and constants are pinned', async () => {
  const a = key(); const h = key();
  const g = mk(a, h);
  const u = Q.use({ key: h, right: g, period: '2026', volumeM3: 100 });
  const good = await Q.verify(u, { type: 'use', network: 'testnet', requireAnchor: false, strict: false, prior: g });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  assert.strictEqual(Q.KIND, 1309);
  assert.strictEqual(Q.FORMAT, 'qwater/1');
  assert.deepStrictEqual([...Q.TYPES], ['allocate', 'use', 'transfer', 'revoke']);
});
