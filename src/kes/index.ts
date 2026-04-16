/**
 * kes-ts — Key Evolving Signature (KES) for Cardano
 *
 * Browser-compatible TypeScript implementation of the SumKES scheme from
 * Cardano's cardano-crypto-class library, using:
 *   - Ed25519 signatures (@noble/curves)
 *   - Blake2b-256 hashing (@noble/hashes)
 *
 * Quick start
 * -----------
 *   import { genKeyKES, signKES, verifyKES, updateKES } from 'kes-ts';
 *
 *   const depth = 6; // 64 periods (Cardano mainnet)
 *   const seed = crypto.getRandomValues(new Uint8Array(32));
 *
 *   let { signKey, verKey } = genKeyKES(seed, depth);
 *
 *   const msg = new TextEncoder().encode('hello');
 *   const sig = signKES(msg, 0, signKey, depth);
 *   console.log(verifyKES(verKey, msg, 0, sig, depth)); // true
 *
 *   signKey = updateKES(signKey, 0, depth)!; // advance to period 1
 *   const sig1 = signKES(msg, 1, signKey, depth);
 *   console.log(verifyKES(verKey, msg, 1, sig1, depth)); // true
 */

export { genKeyKES, deriveVerKeyKES, signKES, updateKES, verifyKES } from './kes.js';
export type { KESKeyPair } from './kes.js';

export {
  sigSize,
  signKeySize,
  totalPeriods,
  ED25519_SK_SIZE,
  ED25519_PK_SIZE,
  ED25519_SIG_SIZE,
  SEED_SIZE,
  VER_KEY_SIZE,
} from './constants.js';

export { expandSeed, hashVKeys, toHex, fromHex } from './utils.js';
