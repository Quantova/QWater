// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');
const OPTS = { network: 'testnet', requireAnchor: false, strict: false };
function right() { const key = Q.generateKey(); const h = Q.generateKey(); return { key, env: Q.allocate({ key, source: 'River Aqua Intake 3', volumeM3: 2000000, basin: 'rhine', jurisdiction: 'de', holder: Q.keyId(h) }) }; }

test('replay as another type or right id is refused', async () => {
  const { env } = right();
  const t = JSON.parse(JSON.stringify(env)); t.type = 'transfer';
  assert.strictEqual((await Q.verify(t, Object.assign({ type: 'transfer' }, OPTS))).status, 'invalid');
  const i = JSON.parse(JSON.stringify(env)); i.statement.rightId = 'f'.repeat(32);
  assert.strictEqual((await Q.verify(i, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
});

test('every signed field is bound', async () => {
  const { env } = right();
  for (const m of [(s) => { s.source = 'X'; }, (s) => { s.volumeM3 += 1; }, (s) => { s.basin = 'nile'; }, (s) => { s.jurisdiction = 'fr'; }, (s) => { s.allocatedAt = '2000-01-01T00:00:00.000Z'; }]) {
    const f = JSON.parse(JSON.stringify(env)); m(f.statement);
    assert.strictEqual((await Q.verify(f, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
  }
});

test('wrong signer, bad base64, extra field, prototype pollution, hidden key, wrong anchor kind', async () => {
  const a = right(); const b = right();
  const ws = JSON.parse(JSON.stringify(a.env)); ws.signer = b.env.signer;
  assert.strictEqual((await Q.verify(ws, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
  const bb = JSON.parse(JSON.stringify(a.env)); bb.signature = bb.signature.slice(0, -4) + 'AAAA';
  assert.strictEqual((await Q.verify(bb, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
  const ex = JSON.parse(JSON.stringify(a.env)); ex.statement.extra = 1;
  assert.strictEqual((await Q.verify(ex, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
  const po = JSON.parse(JSON.stringify(a.env)); po.statement = JSON.parse('{"__proto__":{"x":1},"rightId":"' + a.env.statement.rightId + '"}');
  assert.strictEqual((await Q.verify(po, Object.assign({ type: 'allocate' }, OPTS))).status, 'invalid');
  assert.strictEqual({}.x, undefined);
  assert.strictEqual(JSON.stringify({ k: Q.generateKey() }), '{"k":"SecretKey [hidden]"}');
  const an = JSON.parse(JSON.stringify(a.env)); an.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  assert.strictEqual((await Q.verify(an, { type: 'allocate', network: 'testnet', requireAnchor: true, strict: false })).status, 'invalid');
});
