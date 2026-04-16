/**
 * Self-contained tests for the KES implementation.
 * Run with:  node dist/test.js   (after `npm run build`)
 *
 * Tests cover:
 *  1. Key generation size invariants
 *  2. Signing and verification at period 0
 *  3. Full lifecycle: sign → update → sign → verify across all periods
 *  4. Verification rejects wrong period, wrong message, tampered signature
 *  5. Verification rejects a signature from a different key
 *  6. updateKES returns null at the last period
 *  7. deriveVerKeyKES matches genKeyKES verKey
 *  8. Determinism: same seed → same keys
 */

import {
  genKeyKES,
  deriveVerKeyKES,
  signKES,
  updateKES,
  verifyKES,
  sigSize,
  signKeySize,
  totalPeriods,
  toHex,
} from './index.js';

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;

function ok(condition: boolean, label: string): void {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}`);
    failed++;
  }
}

function section(title: string): void {
  console.log(`\n${title}`);
}

// ---------------------------------------------------------------------------
// Deterministic seed for reproducible tests
// ---------------------------------------------------------------------------
function makeSeed(byte: number): Uint8Array {
  const s = new Uint8Array(32);
  s.fill(byte);
  return s;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

section('1. Size invariants');
for (const depth of [0, 1, 2, 3, 6]) {
  const seed = makeSeed(0xab);
  const { signKey, verKey } = genKeyKES(seed, depth);
  ok(signKey.length === signKeySize(depth), `depth ${depth}: signKey size = ${signKeySize(depth)}`);
  ok(verKey.length === 32,                  `depth ${depth}: verKey size = 32`);

  const msg = new TextEncoder().encode('test');
  const sig = signKES(msg, 0, signKey, depth);
  ok(sig.length === sigSize(depth),          `depth ${depth}: sig size = ${sigSize(depth)}`);
}

section('2. Sign and verify at period 0 (depth 0–4)');
for (const depth of [0, 1, 2, 3, 4]) {
  const seed = makeSeed(depth + 1);
  const { signKey, verKey } = genKeyKES(seed, depth);
  const msg = new TextEncoder().encode(`message for depth ${depth}`);
  const sig = signKES(msg, 0, signKey, depth);
  ok(verifyKES(verKey, msg, 0, sig, depth), `depth ${depth}: valid sig verifies`);
}

section('3. Full lifecycle across all periods (depth 3, 8 periods)');
{
  const depth = 3;
  const seed = makeSeed(0x42);
  let { signKey, verKey } = genKeyKES(seed, depth);
  const msg = new TextEncoder().encode('hello kes');
  const sigs: Uint8Array[] = [];

  // Collect all signatures, updating the key after each.
  for (let t = 0; t < totalPeriods(depth); t++) {
    sigs.push(signKES(msg, t, signKey, depth));
    const next = updateKES(signKey, t, depth);
    if (t < totalPeriods(depth) - 1) {
      ok(next !== null, `period ${t}: updateKES returns a new key`);
      signKey = next!;
    } else {
      ok(next === null, `period ${t} (last): updateKES returns null`);
    }
  }

  // Verify all collected signatures against the (fixed) verKey.
  for (let t = 0; t < totalPeriods(depth); t++) {
    ok(verifyKES(verKey, msg, t, sigs[t], depth), `period ${t}: signature verifies`);
  }
}

section('4. Rejection tests');
{
  const depth = 2;
  const seed = makeSeed(0x77);
  const { signKey, verKey } = genKeyKES(seed, depth);
  const msg = new TextEncoder().encode('authentic');
  const sig = signKES(msg, 0, signKey, depth);

  // Wrong period
  ok(!verifyKES(verKey, msg, 1, sig, depth), 'wrong period rejected');

  // Wrong message
  const badMsg = new TextEncoder().encode('tampered');
  ok(!verifyKES(verKey, badMsg, 0, sig, depth), 'wrong message rejected');

  // Tampered signature (flip a byte)
  const tampered = sig.slice();
  tampered[0] ^= 0xff;
  ok(!verifyKES(verKey, msg, 0, tampered, depth), 'tampered signature rejected');

  // Signature for period 1 does not verify at period 0
  const updatedSk = updateKES(signKey, 0, depth)!;
  const sig1 = signKES(msg, 1, updatedSk, depth);
  ok(!verifyKES(verKey, msg, 0, sig1, depth), 'period-1 sig rejected at period 0');
  ok( verifyKES(verKey, msg, 1, sig1, depth), 'period-1 sig accepted at period 1');
}

section('5. Different key pairs do not cross-verify');
{
  const depth = 1;
  const { signKey: sk1, verKey: vk1 } = genKeyKES(makeSeed(0x01), depth);
  const { verKey: vk2 }               = genKeyKES(makeSeed(0x02), depth);
  const msg = new TextEncoder().encode('cross check');
  const sig = signKES(msg, 0, sk1, depth);
  ok( verifyKES(vk1, msg, 0, sig, depth), 'verifies under correct vk');
  ok(!verifyKES(vk2, msg, 0, sig, depth), 'rejected under different vk');
}

section('6. deriveVerKeyKES matches genKeyKES verKey');
{
  for (const depth of [0, 1, 3, 6]) {
    const seed = makeSeed(depth + 10);
    const { signKey, verKey } = genKeyKES(seed, depth);
    const derived = deriveVerKeyKES(signKey, depth);
    const match = verKey.every((b, i) => b === derived[i]);
    ok(match, `depth ${depth}: deriveVerKeyKES matches genKeyKES`);
  }
}

section('7. Determinism: same seed → same keys');
{
  const depth = 3;
  const seed = makeSeed(0xde);
  const { signKey: sk1, verKey: vk1 } = genKeyKES(seed, depth);
  const { signKey: sk2, verKey: vk2 } = genKeyKES(seed, depth);
  ok(vk1.every((b, i) => b === vk2[i]), 'same verKey from same seed');
  ok(sk1.every((b, i) => b === sk2[i]), 'same signKey from same seed');
}

section('8. Verify Sum6KES vector (depth 6, 64 periods)');
{
  const depth = 6;
  const seed = makeSeed(0xca);
  const { signKey, verKey } = genKeyKES(seed, depth);
  const msg = new TextEncoder().encode('cardano');
  const sig = signKES(msg, 0, signKey, depth);

  ok(sig.length === sigSize(depth), `Sum6KES sig length = ${sigSize(depth)}`);
  ok(verifyKES(verKey, msg, 0, sig, depth), 'Sum6KES: period 0 verifies');

  // Print key material for external cross-validation
  console.log(`  verKey  (hex): ${toHex(verKey)}`);
  console.log(`  sig[0]  (hex): ${toHex(sig.subarray(0, 64))}`);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n${'─'.repeat(50)}`);
console.log(`Passed: ${passed}  Failed: ${failed}`);
if (failed > 0) {
  process.exit(1);
}
