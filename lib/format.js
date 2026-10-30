// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qwater/1';
const ALGORITHM = 'ML-DSA-65';
const KIND = 1309;
const TYPES = Object.freeze(['allocate', 'use', 'transfer', 'revoke']);
const KEY_DOMAIN = Buffer.from('quantova/qwater/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qwater/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qwater/anchor/1', 'ascii');
const RIGHT_DOMAIN = Buffer.from('quantova/qwater/right/1', 'ascii');
const MAGIC = Buffer.from('QH2O', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const LABEL_MAX = 200;
const NOTE_MAX = 1000;
const REF_MAX = 120;
const MAX_VOLUME_M3 = 1000000000000000;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const CODE = /^[a-z][a-z0-9_]{0,39}$/;
const IDENT = /^[A-Za-z0-9][A-Za-z0-9 ./-]{0,119}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;

const FIELDS = Object.freeze({
  allocate: ['rightId', 'source', 'volumeM3', 'basin', 'jurisdiction', 'holderKeyId', 'authorityKeyId', 'authorityLabel', 'allocatedAt', 'note'],
  use: ['rightId', 'rightRef', 'period', 'volumeM3', 'reporterKeyId', 'reporterLabel', 'reportedAt', 'note'],
  transfer: ['rightId', 'rightRef', 'fromKeyId', 'toKeyId', 'toLabel', 'transferredAt', 'note'],
  revoke: ['rightId', 'rightRef', 'authorityKeyId', 'reason', 'revokedAt', 'note'],
});

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QWATER_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QWATER_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!((ArrayBuffer.isView(publicKey) && publicKey instanceof Uint8Array)) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function rightRefOf(secret, reference) {
  if (!((ArrayBuffer.isView(secret) && secret instanceof Uint8Array)) || secret.length !== 32) reject('the right secret is a 32 byte Uint8Array held by the authority');
  if (new Set(secret).size < 13) reject('a right secret made of too few different byte values is refused, draw it from a secure random source');
  if (typeof reference !== 'string' || reference.length === 0 || reference.length > REF_MAX) reject('the right reference is 1 to ' + REF_MAX + ' characters');
  if (!IDENT.test(reference)) reject('the right reference holds letters, digits, spaces, dots, slashes or hyphens and starts with a letter or digit');
  return sha3(RIGHT_DOMAIN, Buffer.from([0]), Buffer.from(secret), Buffer.from(reference, 'utf8')).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' cannot be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function refProblem(value, what) {
  if (typeof value !== 'string' || !HEX32.test(value)) return what + ' must be 64 lowercase hex characters';
  return null;
}

function codeProblem(value, what) {
  if (typeof value !== 'string' || !CODE.test(value)) return what + ' must be lowercase letters, digits or underscores, 1 to 40 characters, starting with a letter';
  return null;
}

function intProblem(value, max, what) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) return what + ' must be a whole number of at least 1';
  if (value > max) return what + ' is larger than ' + max;
  return null;
}

function identProblem(value, what) {
  if (typeof value !== 'string' || value.length === 0 || value.length > REF_MAX) return what + ' is 1 to ' + REF_MAX + ' characters';
  if (!IDENT.test(value)) return what + ' holds letters, digits, spaces, dots, slashes or hyphens and starts with a letter or digit';
  return null;
}

function statementProblem(type, st) {
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  const fields = FIELDS[type];
  if (Object.keys(st).sort().join(',') !== fields.slice().sort().join(',')) return 'a ' + type + ' statement holds exactly ' + fields.join(', ');
  const checks = [];
  checks.push(pattern(st.rightId, HEX16, 'rightId', '32 lowercase hex characters'));
  checks.push(textProblem(st.note, NOTE_MAX, 'note', false));
  if (type === 'allocate') {
    checks.push(identProblem(st.source, 'source'));
    checks.push(intProblem(st.volumeM3, MAX_VOLUME_M3, 'volumeM3'));
    checks.push(codeProblem(st.basin, 'basin'));
    checks.push(codeProblem(st.jurisdiction, 'jurisdiction'));
    checks.push(pattern(st.holderKeyId, HEX32, 'holderKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.authorityKeyId, HEX32, 'authorityKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.authorityLabel, LABEL_MAX, 'authorityLabel', false));
    checks.push(timeProblem(st.allocatedAt, 'allocatedAt'));
  } else if (type === 'use') {
    checks.push(refProblem(st.rightRef, 'rightRef'));
    checks.push(identProblem(st.period, 'period'));
    checks.push(intProblem(st.volumeM3, MAX_VOLUME_M3, 'volumeM3'));
    checks.push(pattern(st.reporterKeyId, HEX32, 'reporterKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.reporterLabel, LABEL_MAX, 'reporterLabel', false));
    checks.push(timeProblem(st.reportedAt, 'reportedAt'));
  } else if (type === 'transfer') {
    checks.push(refProblem(st.rightRef, 'rightRef'));
    checks.push(pattern(st.fromKeyId, HEX32, 'fromKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.toKeyId, HEX32, 'toKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.toLabel, LABEL_MAX, 'toLabel', false));
    checks.push(timeProblem(st.transferredAt, 'transferredAt'));
    if (!checks.some(Boolean) && st.fromKeyId === st.toKeyId) checks.push('the receiving key must differ from the sending key');
  } else {
    checks.push(refProblem(st.rightRef, 'rightRef'));
    checks.push(pattern(st.authorityKeyId, HEX32, 'authorityKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.reason, LABEL_MAX, 'reason', true));
    checks.push(timeProblem(st.revokedAt, 'revokedAt'));
  }
  return checks.find(Boolean) || null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type), hex(st.rightId)];
  if (type === 'allocate') {
    parts.push(utf8(st.source), u64(st.volumeM3), ascii(st.basin), ascii(st.jurisdiction), hex(st.holderKeyId), hex(st.authorityKeyId), utf8(st.authorityLabel), ascii(st.allocatedAt));
  } else if (type === 'use') {
    parts.push(hex(st.rightRef), utf8(st.period), u64(st.volumeM3), hex(st.reporterKeyId), utf8(st.reporterLabel), ascii(st.reportedAt));
  } else if (type === 'transfer') {
    parts.push(hex(st.rightRef), hex(st.fromKeyId), hex(st.toKeyId), utf8(st.toLabel), ascii(st.transferredAt));
  } else {
    parts.push(hex(st.rightRef), hex(st.authorityKeyId), utf8(st.reason), ascii(st.revokedAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parse(envelope) {
  exactKeys(envelope, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (envelope.format !== FORMAT) fail('format must be ' + FORMAT);
  if (envelope.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(envelope.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(envelope.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof envelope.signer.id !== 'string' || !HEX32.test(envelope.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(envelope.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  let statement;
  try {
    statement = plainCopy(envelope.statement);
  } catch (e) {
    fail('the statement is not plain data');
  }
  const problem = statementProblem(envelope.type, statement);
  if (problem) fail(problem);
  const signature = decodeBase64(envelope.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(envelope, 'anchor') ? envelope.anchor : undefined;
  return { type: envelope.type, signerId: envelope.signer.id, publicKey, statement, signature, anchor };
}

function encoded(parsed) {
  return payload(parsed.type, parsed.statement);
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature);
}

module.exports = {
  FORMAT, ALGORITHM, KIND, TYPES, FIELDS, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, LABEL_MAX, NOTE_MAX, REF_MAX, MAX_VOLUME_M3,
  sha3, keyIdOf, rightRefOf, textProblem, timeProblem, statementProblem, payload, encoded, parse, refOf, anchorDigest, reject, plainCopy,
};
