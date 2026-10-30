// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type RecordType = 'allocate' | 'use' | 'transfer' | 'revoke';
export interface KeyDescription { format: 'qwater-key/1'; algorithm: 'ML-DSA-65'; id: string; publicKey: string; }
export type Party = string | Uint8Array | KeyDescription;
export interface Signer { id: string; publicKey: string; }
export interface Envelope<T = Record<string, unknown>> { format: 'qwater/1'; type: RecordType; algorithm: 'ML-DSA-65'; signer: Signer; statement: T; signature: string; anchor?: unknown; }

export interface AllocateOptions { key: Uint8Array; source: string; volumeM3: number; basin: string; jurisdiction: string; holder: Party; authorityLabel?: string; allocatedAt?: string; note?: string; }
export interface UseOptions { key: Uint8Array; right: Envelope; period: string; volumeM3: number; reporterLabel?: string; reportedAt?: string; note?: string; }
export interface TransferOptions { key: Uint8Array; right: Envelope; to: Party; toLabel?: string; transferredAt?: string; note?: string; }
export interface RevokeOptions { key: Uint8Array; right: Envelope; reason: string; revokedAt?: string; note?: string; }
export interface AnchorOptions { seed?: Uint8Array; index?: number; network?: string; rpc?: string; clients?: unknown[]; trustSingleEndpoint?: boolean; trustCustomEndpoints?: boolean; allowLoopback?: boolean; maxFee?: string | number | bigint; meter?: string | number | bigint; timeoutMs?: number; onPending?: (pending: unknown) => void; signal?: AbortSignal; }
export interface VerifyOptions { type?: RecordType; prior?: Envelope; rightId?: string; signerKeyId?: string; signerPublicKey?: string | Uint8Array; network: string; strict?: boolean; requireAnchor?: boolean; maxAnchorDelay?: number; at?: string; deadlineMs?: number; rpc?: string; clients?: unknown[]; trustSingleEndpoint?: boolean; trustCustomEndpoints?: boolean; allowLoopback?: boolean; }
export interface Check { name: string; ok: boolean; detail: string; transport: boolean; indeterminate: boolean; unproven: boolean; }
export interface VerifyResult { valid: boolean; status: 'valid' | 'unproven' | 'indeterminate' | 'invalid'; type: RecordType | null; rightId?: string; signerId?: string; statement?: Record<string, unknown>; anchoredAt?: string | null; endpoints: string[]; officialEndpoints: boolean | null; checks: Check[]; }

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function rightRef(secret: Uint8Array, reference: string): string;
export function allocate(options: AllocateOptions): Envelope;
export function use(options: UseOptions): Envelope;
export function transfer(options: TransferOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qwater/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1309;
export const TYPES: readonly RecordType[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
