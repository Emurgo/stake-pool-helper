/**
 * Size constants matching cardano-crypto-class KES implementation.
 *
 * Cardano uses SumKES over Ed25519DSIGN with Blake2b-256:
 *   - SingleKES wraps Ed25519
 *   - SumKES<d> creates 2^d periods by binary-tree composition
 *
 * Production Cardano uses Sum6KES (64 periods) or Sum7KES (128 periods).
 */

/** Ed25519 seed (private key) size in bytes */
export const ED25519_SK_SIZE = 32;

/** Ed25519 public key size in bytes */
export const ED25519_PK_SIZE = 32;

/** Ed25519 signature size in bytes */
export const ED25519_SIG_SIZE = 64;

/**
 * Seed size used for KES key generation and expansion.
 * Matches SeedSize for Blake2b-256 in cardano-crypto-class.
 */
export const SEED_SIZE = 32;

/**
 * Verification key size at every depth.
 *
 * - Depth 0 (SingleKES): the raw 32-byte Ed25519 public key
 * - Depth d (SumKES):    Blake2b-256(vk0 || vk1) = 32 bytes
 *
 * Always 32 bytes.
 */
export const VER_KEY_SIZE = 32;

/**
 * Compute the byte size of a serialised signature at a given KES depth.
 *
 * Recurrence from Sum.hs rawSerialiseSigKES:
 *   SigSize(0) = ED25519_SIG_SIZE                     (64 bytes)
 *   SigSize(d) = SigSize(d-1) + 2 * VER_KEY_SIZE      (+64 bytes per level)
 *
 * Closed form: SigSize(d) = (d + 1) * 64
 */
export function sigSize(depth: number): number {
  return (depth + 1) * ED25519_SIG_SIZE;
}

/**
 * Compute the byte size of a serialised signing key at a given KES depth.
 *
 * Recurrence from Sum.hs rawSerialiseSignKeyKES:
 *   SignKeySize(0) = ED25519_SK_SIZE                               (32 bytes)
 *   SignKeySize(d) = SignKeySize(d-1) + SEED_SIZE + 2*VER_KEY_SIZE (+96 bytes per level)
 *
 * Closed form: SignKeySize(d) = 32 + d * 96
 */
export function signKeySize(depth: number): number {
  return ED25519_SK_SIZE + depth * (SEED_SIZE + 2 * VER_KEY_SIZE);
}

/**
 * Total number of KES periods available at a given depth.
 *   totalPeriods(0) = 1   (SingleKES: one period, period 0)
 *   totalPeriods(d) = 2^d
 */
export function totalPeriods(depth: number): number {
  return 1 << depth;
}
