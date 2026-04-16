/**
 * Key Evolving Signature (KES) — pure TypeScript implementation.
 *
 * Implements the SumKES scheme from Cardano's cardano-crypto-class library:
 *   cardano-crypto-class/src/Cardano/Crypto/KES/{Class,Single,Sum}.hs
 *
 * Algorithm overview
 * ------------------
 * KES is a forward-secure signature scheme.  A signing key covers exactly
 * one time period; calling updateKES irreversibly advances it to the next
 * period so that the previous period's key material cannot be recovered.
 *
 * SumKES builds 2^d periods by binary-tree composition of Ed25519 leaves:
 *
 *   depth 0 = SingleKES  → 2^0 = 1 period  (one Ed25519 key)
 *   depth 1 = Sum1KES    → 2^1 = 2 periods
 *   depth 6 = Sum6KES    → 2^6 = 64 periods  ← typical Cardano mainnet
 *   depth 7 = Sum7KES    → 2^7 = 128 periods
 *
 * Byte layout
 * -----------
 * VerKey is always 32 bytes (Ed25519 public key at depth 0, Blake2b-256
 * hash of the two child VerKeys at every SumKES level).
 *
 * SignKey layout at depth d  (= signKeySize(d) bytes):
 *   [ sk0 : signKeySize(d-1) ] [ r1 : 32 ] [ vk0 : 32 ] [ vk1 : 32 ]
 *
 * Signature layout at depth d  (= sigSize(d) bytes):
 *   [ childSig : sigSize(d-1) ] [ vk0 : 32 ] [ vk1 : 32 ]
 *
 * Depth 0 (SingleKES):
 *   SignKey = 32-byte Ed25519 seed
 *   Sig     = 64-byte Ed25519 signature
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import {
  ED25519_SK_SIZE,
  ED25519_SIG_SIZE,
  SEED_SIZE,
  VER_KEY_SIZE,
  sigSize,
  signKeySize,
  totalPeriods,
} from './constants.js';
import { expandSeed, hashVKeys, concat, bytesEqual } from './utils.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A KES key pair returned by genKeyKES. */
export interface KESKeyPair {
  /** Signing key bytes. Length = signKeySize(depth). Keep this secret. */
  signKey: Uint8Array;
  /** Verification key bytes. Always 32 bytes. Safe to publish. */
  verKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * Generate a fresh KES signing/verification key pair.
 *
 * @param seed  - Random 32-byte seed (must be high-entropy, use crypto.getRandomValues).
 * @param depth - Tree depth.  Use 6 for 64 periods (Cardano mainnet), 7 for 128.
 *
 * Matches Cardano.Crypto.KES.Sum genKeyKES:
 *   r0 = expandSeed(seed)[0]
 *   r1 = expandSeed(seed)[1]
 *   sk0 = genKeyKES(r0, depth-1)
 *   vk0 = deriveVerKeyKES(sk0)
 *   vk1 = deriveVerKeyKES(genKeyKES(r1, depth-1))   ← only vk1 is kept, r1 is stored
 *   signKey = sk0 || r1 || vk0 || vk1
 *   verKey  = Blake2b-256(vk0 || vk1)
 */
export function genKeyKES(seed: Uint8Array, depth: number): KESKeyPair {
  if (seed.length !== SEED_SIZE) {
    throw new Error(`genKeyKES: seed must be ${SEED_SIZE} bytes, got ${seed.length}`);
  }
  if (depth < 0 || !Number.isInteger(depth)) {
    throw new Error(`genKeyKES: depth must be a non-negative integer, got ${depth}`);
  }

  if (depth === 0) {
    // SingleKES: Ed25519 key from seed.
    // rawSerialiseSignKeyKES for Ed25519DSIGN = the 32-byte seed.
    const verKey = ed25519.getPublicKey(seed);
    const signKey = seed.slice(); // copy so callers cannot mutate the input seed
    return { signKey, verKey };
  }

  // SumKES: expand the seed into two child seeds.
  const [r0, r1] = expandSeed(seed);

  // Generate the left subtree (sk0 + vk0).
  const left = genKeyKES(r0, depth - 1);

  // Generate the right subtree only to obtain vk1; discard its signing key.
  const { verKey: vk1 } = genKeyKES(r1, depth - 1);

  const verKey = hashVKeys(left.verKey, vk1);

  // sk0 || r1 || vk0 || vk1
  const signKey = concat(left.signKey, r1, left.verKey, vk1);

  return { signKey, verKey };
}

// ---------------------------------------------------------------------------
// Verification key derivation
// ---------------------------------------------------------------------------

/**
 * Derive the verification key from a signing key.
 *
 * At depth 0: returns the Ed25519 public key.
 * At depth d: returns Blake2b-256(vk0 || vk1) extracted from the signing key.
 */
export function deriveVerKeyKES(signKey: Uint8Array, depth: number): Uint8Array {
  assertSignKeySize(signKey, depth, 'deriveVerKeyKES');

  if (depth === 0) {
    return ed25519.getPublicKey(signKey);
  }

  const { vk0, vk1 } = parseSumSignKey(signKey, depth);
  return hashVKeys(vk0, vk1);
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Sign a message at the given period.
 *
 * @param message - Arbitrary byte array to sign.
 * @param period  - Current period (0-indexed).  Must be < totalPeriods(depth).
 * @param signKey - The current signing key bytes.
 * @param depth   - Tree depth.
 * @returns Signature bytes.  Length = sigSize(depth).
 *
 * Matches Cardano.Crypto.KES.Sum signKES:
 *   if period < childPeriods: sign in left subtree with period t
 *   else:                     sign in right subtree with period t - childPeriods
 *   Both paths use sk0 — after the boundary transition in updateKES, sk0 IS
 *   the right subtree's signing key.
 *   Signature = childSig || vk0 || vk1
 */
export function signKES(
  message: Uint8Array,
  period: number,
  signKey: Uint8Array,
  depth: number,
): Uint8Array {
  assertSignKeySize(signKey, depth, 'signKES');
  assertPeriodInRange(period, depth, 'signKES');

  if (depth === 0) {
    // SingleKES: sign with Ed25519.
    return ed25519.sign(message, signKey);
  }

  const childPeriods = totalPeriods(depth - 1);
  const { sk0, vk0, vk1 } = parseSumSignKey(signKey, depth);

  const childSig =
    period < childPeriods
      ? signKES(message, period, sk0, depth - 1)
      : signKES(message, period - childPeriods, sk0, depth - 1);

  return concat(childSig, vk0, vk1);
}

// ---------------------------------------------------------------------------
// Key evolution
// ---------------------------------------------------------------------------

/**
 * Evolve the signing key to the next period (forward-secrecy update).
 *
 * Returns the updated signing key, or null if already at the last period.
 * The previous signing key is no longer useful after this call.
 *
 * @param signKey - Current signing key bytes.
 * @param period  - Current period (0-indexed).
 * @param depth   - Tree depth.
 *
 * Matches Cardano.Crypto.KES.Sum updateKES:
 *   Let T = totalPeriods(depth-1)   (number of periods per subtree)
 *
 *   t+1 < T    → still in left subtree: evolve sk0
 *   t+1 == T   → boundary: generate new sk0 from r1, zero-out r1
 *   t+1 > T    → in right subtree: evolve sk0 (already the right-subtree key)
 */
export function updateKES(
  signKey: Uint8Array,
  period: number,
  depth: number,
): Uint8Array | null {
  assertSignKeySize(signKey, depth, 'updateKES');
  assertPeriodInRange(period, depth, 'updateKES');

  if (period >= totalPeriods(depth) - 1) {
    return null; // already at the last period
  }

  if (depth === 0) {
    // SingleKES has only one period and cannot evolve.
    return null;
  }

  const childPeriods = totalPeriods(depth - 1);
  const { sk0, r1, vk0, vk1 } = parseSumSignKey(signKey, depth);

  let newSk0: Uint8Array;

  if (period + 1 < childPeriods) {
    // Still inside the left subtree — evolve sk0 one step.
    const evolved = updateKES(sk0, period, depth - 1);
    if (evolved === null) throw new Error('updateKES: unexpected null from child');
    newSk0 = evolved;
    // r1, vk0, vk1 are unchanged
    return concat(newSk0, r1, vk0, vk1);
  } else if (period + 1 === childPeriods) {
    // Boundary: transition from left subtree to right subtree.
    // Generate the right subtree's signing key from r1, then erase r1.
    newSk0 = genKeyKES(r1, depth - 1).signKey;
    const zeroR1 = new Uint8Array(SEED_SIZE); // r1 is no longer needed
    // vk0 and vk1 remain the same (they are the fixed pair for this SumKES node)
    return concat(newSk0, zeroR1, vk0, vk1);
  } else {
    // Inside the right subtree — evolve sk0 (which is already the right-subtree key).
    const evolved = updateKES(sk0, period - childPeriods, depth - 1);
    if (evolved === null) throw new Error('updateKES: unexpected null from child');
    newSk0 = evolved;
    // r1 is already zeroed from the boundary transition
    return concat(newSk0, r1, vk0, vk1);
  }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Verify a KES signature.
 *
 * @param verKey    - 32-byte verification key.
 * @param message   - The original signed message.
 * @param period    - The period at which the message was signed.
 * @param signature - Signature bytes from signKES.
 * @param depth     - Tree depth (must match the key pair's depth).
 * @returns true if the signature is valid, false otherwise.
 *
 * Matches Cardano.Crypto.KES.Sum verifyKES:
 *   1. Parse (childSig, vk0, vk1) from the signature.
 *   2. Verify that Blake2b-256(vk0 || vk1) == verKey.
 *   3. Route to the correct child based on period and recursively verify.
 */
export function verifyKES(
  verKey: Uint8Array,
  message: Uint8Array,
  period: number,
  signature: Uint8Array,
  depth: number,
): boolean {
  if (verKey.length !== VER_KEY_SIZE) return false;
  if (signature.length !== sigSize(depth)) return false;
  if (period < 0 || period >= totalPeriods(depth)) return false;

  if (depth === 0) {
    // SingleKES: standard Ed25519 verification.
    try {
      return ed25519.verify(signature, message, verKey);
    } catch {
      return false;
    }
  }

  // SumKES: parse the signature.
  const childSigLen = sigSize(depth - 1);
  const childSig = signature.subarray(0, childSigLen);
  const sigVk0 = signature.subarray(childSigLen, childSigLen + VER_KEY_SIZE);
  const sigVk1 = signature.subarray(childSigLen + VER_KEY_SIZE, childSigLen + 2 * VER_KEY_SIZE);

  // Step 1: check that the embedded (vk0, vk1) hashes to the provided verKey.
  const expectedHash = hashVKeys(sigVk0, sigVk1);
  if (!bytesEqual(expectedHash, verKey)) return false;

  // Step 2: route to the child that was used for this period.
  const childPeriods = totalPeriods(depth - 1);
  if (period < childPeriods) {
    return verifyKES(sigVk0, message, period, childSig, depth - 1);
  } else {
    return verifyKES(sigVk1, message, period - childPeriods, childSig, depth - 1);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Parts of a SumKES signing key extracted by position. */
interface SumSignKeyParts {
  /** Current child (left or right after transition) signing key. */
  sk0: Uint8Array;
  /** Seed for the right subtree (zeroed after boundary transition). */
  r1: Uint8Array;
  /** Left child verification key (fixed for the lifetime of this node). */
  vk0: Uint8Array;
  /** Right child verification key (fixed for the lifetime of this node). */
  vk1: Uint8Array;
}

/**
 * Parse the four fields from a SumKES signing key byte array.
 *
 * Layout: [ sk0 : signKeySize(d-1) ] [ r1 : 32 ] [ vk0 : 32 ] [ vk1 : 32 ]
 */
function parseSumSignKey(signKey: Uint8Array, depth: number): SumSignKeyParts {
  const sk0Size = signKeySize(depth - 1);
  let offset = 0;

  const sk0 = signKey.subarray(offset, offset + sk0Size);
  offset += sk0Size;

  const r1 = signKey.subarray(offset, offset + SEED_SIZE);
  offset += SEED_SIZE;

  const vk0 = signKey.subarray(offset, offset + VER_KEY_SIZE);
  offset += VER_KEY_SIZE;

  const vk1 = signKey.subarray(offset, offset + VER_KEY_SIZE);

  return { sk0, r1, vk0, vk1 };
}

function assertSignKeySize(key: Uint8Array, depth: number, fn: string): void {
  const expected = signKeySize(depth);
  if (key.length !== expected) {
    throw new Error(`${fn}: signing key must be ${expected} bytes for depth ${depth}, got ${key.length}`);
  }
}

function assertPeriodInRange(period: number, depth: number, fn: string): void {
  if (!Number.isInteger(period) || period < 0 || period >= totalPeriods(depth)) {
    throw new Error(
      `${fn}: period ${period} is out of range [0, ${totalPeriods(depth) - 1}] for depth ${depth}`,
    );
  }
}
