// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const W = require('./lib/water');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: W.generateKey,
  publicKey: W.publicKey,
  keyId: W.keyId,
  describeKey: W.describeKey,
  rightRef: W.rightRef,
  allocate: W.allocate,
  use: W.use,
  transfer: W.transfer,
  revoke: W.revoke,
  anchor: W.anchor,
  complete: W.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
