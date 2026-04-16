/**
 * Utility functions: seed expansion and verification-key hashing.
 *
 * These match the behaviour of Cardano.Crypto.Libsodium.Hash and
 * Cardano.Crypto.KES.Sum seed-expansion in cardano-crypto-class.
 */

import { blake2b } from '@noble/hashes/blake2.js';
import { SEED_SIZE, VER_KEY_SIZE } from './constants.js';

/**
 * Expand one 32-byte seed into two independent child seeds using Blake2b-256.
 *
 * Matches cardano-crypto-class expandSeed:
 *   r0 = Blake2b-256( 0x01 || seed )
 *   r1 = Blake2b-256( 0x02 || seed )
 *
 * The prefix byte prevents r0 == r1 and ensures domain separation.
 */
export function expandSeed(seed: Uint8Array): [Uint8Array, Uint8Array] {
  if (seed.length !== SEED_SIZE) {
    throw new Error(`expandSeed: expected ${SEED_SIZE}-byte seed, got ${seed.length}`);
  }
  const buf = new Uint8Array(1 + SEED_SIZE);
  buf.set(seed, 1);

  buf[0] = 1;
  const r0 = blake2b(buf, { dkLen: 32 });

  buf[0] = 2;
  const r1 = blake2b(buf, { dkLen: 32 });

  return [r0, r1];
}

/**
 * Compute the SumKES verification key from two child verification keys.
 *
 * Matches hashPairOfVKeys in Sum.hs:
 *   vk = Blake2b-256( vk0 || vk1 )
 *
 * Both vk0 and vk1 are always VER_KEY_SIZE bytes.
 */
export function hashVKeys(vk0: Uint8Array, vk1: Uint8Array): Uint8Array {
  if (vk0.length !== VER_KEY_SIZE || vk1.length !== VER_KEY_SIZE) {
    throw new Error(`hashVKeys: each key must be ${VER_KEY_SIZE} bytes`);
  }
  const combined = new Uint8Array(VER_KEY_SIZE * 2);
  combined.set(vk0, 0);
  combined.set(vk1, VER_KEY_SIZE);
  return blake2b(combined, { dkLen: 32 });
}

/** Concatenate multiple byte arrays into one. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/**
 * Constant-time byte equality check.
 * Avoids early-exit timing side-channels when comparing key material.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Encode a Uint8Array to a lowercase hex string (for display / debugging). */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Decode a lowercase hex string to a Uint8Array. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('fromHex: odd-length hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
