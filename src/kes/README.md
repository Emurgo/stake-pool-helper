# KES — Key Evolving Signature

A pure TypeScript implementation of the **SumKES** scheme used by Cardano,
derived directly from the Haskell source in
[`IntersectMBO/cardano-base`](https://github.com/IntersectMBO/cardano-base),
package `cardano-crypto-class`.

---

## Background

### What is KES?

KES (Key Evolving Signature) is a **forward-secure** signature scheme.
The signing key is divided into a fixed number of _periods_.  At each period
boundary the key is irreversibly _evolved_: old key material is erased so that
a compromise of the current signing key does not allow an attacker to forge
signatures for past periods.

Cardano block producers use KES to sign blocks.  The KES signing key is
rotated every `slotsPerKESPeriod` slots.  The verification key (embedded in
the operational certificate) stays constant for the lifetime of the key pair.

### Academic basis

SumKES implements the **binary-tree construction** from:

> Itkis & Reyzin, "SiBIR: Signer-Base Intrusion-Resilient Signatures" (2002)
> Malkin, Micciancio & Miner, "Efficient Generic Forward-Secure Signatures
> with an Unbounded Number of Time Periods" (Eurocrypt 2002)

---

## Upstream Haskell source

The implementation was read from these files in `cardano-crypto-class`
(commit referenced: `IntersectMBO/cardano-base`, `master`):

| File | Role |
|---|---|
| `Cardano/Crypto/KES/Class.hs` | Abstract `KESAlgorithm` type class |
| `Cardano/Crypto/KES/Single.hs` | `SingleKES` — wraps one Ed25519 key pair (depth 0) |
| `Cardano/Crypto/KES/Sum.hs` | `SumKES` — binary-tree composition (depth d) |
| `Cardano/Crypto/DSIGN/Ed25519.hs` | Ed25519 sign / verify via libsodium |
| `Cardano/Crypto/Libsodium/Hash.hs` | Blake2b-256 seed expansion |
| `Cardano/Crypto/Seed.hs` | Seed abstraction |

The production Cardano mainnet type alias is `Sum6KES Ed25519DSIGN Blake2b`
(64 periods, depth 6).

---

## Algorithm derivation

### Primitives

| Primitive | Haskell | TypeScript (this codebase) |
|---|---|---|
| Signing | `Ed25519DSIGN` via libsodium | `ed25519` from `@noble/curves` |
| Hashing | `Blake2b` (256-bit output) via libsodium | `blake2b` from `@noble/hashes` |

### Size recurrences

These are closed forms of the recurrences in `Sum.hs`:

```
VerKeySize(d)     = 32            (always; hash output or Ed25519 pubkey)
SeedSize          = 32            (Blake2b-256 output width)

SignKeySize(0)    = 32            (Ed25519 seed)
SignKeySize(d)    = SignKeySize(d-1) + 32 + 2×32
                  = 32 + d × 96

SigSize(0)        = 64            (Ed25519 signature)
SigSize(d)        = SigSize(d-1) + 2×32
                  = (d + 1) × 64

TotalPeriods(d)   = 2^d
```

For the mainnet depth of 6:

| | Bytes |
|---|---|
| `signKey` | 608 |
| `verKey` | 32 |
| `signature` | 448 |
| Periods | 64 |

### Seed expansion — `expandSeed`

Maps to `Cardano.Crypto.Libsodium.Hash` / the seed-splitting used in
`Sum.hs genKeyKES`:

```
r0 = Blake2b-256( 0x01 ‖ seed )
r1 = Blake2b-256( 0x02 ‖ seed )
```

The prefix byte (`0x01` / `0x02`) provides domain separation so that
`r0 ≠ r1` even when the hash function is collision-resistant but not
a PRF.

### Verification-key hashing — `hashVKeys`

Maps to `hashPairOfVKeys` in `Sum.hs`:

```
vk_parent = Blake2b-256( vk_left ‖ vk_right )
```

This is a Merkle-style hash that commits to both child verification keys.
Every signature carries the two child keys, and verification checks the hash
before recursing — preventing an attacker from substituting a different child
key.

---

## Key generation — `genKeyKES`

**Haskell reference:** `genKeyKES` in `Sum.hs` / `Single.hs`

### Base case (depth 0 — SingleKES)

```
input:  seed : Bytes[32]
output: signKey = seed
        verKey  = Ed25519.getPublicKey(seed)
```

### Recursive case (depth d — SumKES)

```
input:  seed : Bytes[32], depth d

1.  (r0, r1) = expandSeed(seed)
2.  (sk0, vk0) = genKeyKES(r0, d-1)     // left subtree
3.  (  _, vk1) = genKeyKES(r1, d-1)     // right subtree — signing key DISCARDED
4.  verKey  = Blake2b-256(vk0 ‖ vk1)
5.  signKey = sk0 ‖ r1 ‖ vk0 ‖ vk1      // r1 retained; right sk never stored
```

The right subtree's signing key is generated only to derive `vk1` and then
immediately discarded.  `r1` is stored so it can be regenerated at the period
boundary during `updateKES`.

### SignKey byte layout

```
offset 0                  : sk0   — signKeySize(d-1) bytes
offset signKeySize(d-1)   : r1    — 32 bytes  (seed for right subtree)
offset signKeySize(d-1)+32: vk0   — 32 bytes  (left child verKey)
offset signKeySize(d-1)+64: vk1   — 32 bytes  (right child verKey)
```

---

## Signing — `signKES`

**Haskell reference:** `signKES` in `Sum.hs` / `Single.hs`

### Base case (depth 0)

```
sig = Ed25519.sign(message, signKey)          // 64 bytes
```

### Recursive case (depth d)

```
T = 2^(d-1)   // periods per subtree

if period < T:
    childSig = signKES(message, period,   sk0, d-1)
else:
    childSig = signKES(message, period-T, sk0, d-1)

sig = childSig ‖ vk0 ‖ vk1
```

After the boundary transition in `updateKES`, `sk0` _is_ the right subtree's
signing key, so the same field always holds "the currently active subtree key".

### Signature byte layout

```
offset 0            : childSig — sigSize(d-1) bytes
offset sigSize(d-1) : vk0      — 32 bytes
offset sigSize(d-1)+32: vk1    — 32 bytes
```

---

## Key evolution — `updateKES`

**Haskell reference:** `updateKES` in `Sum.hs`

Returns a new signing key covering period `t+1`, or `null` at the last period.

```
T = 2^(d-1)   // periods per subtree

case t+1 < T:
    // Still in the left subtree — evolve sk0 one step.
    newSk0 = updateKES(sk0, t, d-1)
    return newSk0 ‖ r1 ‖ vk0 ‖ vk1

case t+1 == T:
    // Boundary: switch from left to right subtree.
    newSk0 = genKeyKES(r1, d-1).signKey   // materialise the right subtree
    zeroR1 = Bytes[32]{0}                 // erase r1 — forward secrecy
    return newSk0 ‖ zeroR1 ‖ vk0 ‖ vk1

case t+1 > T:
    // Already in the right subtree — continue evolving.
    newSk0 = updateKES(sk0, t-T, d-1)
    return newSk0 ‖ r1 ‖ vk0 ‖ vk1      // r1 is already zero from boundary
```

`vk0` and `vk1` never change — they are the fixed child verification keys for
this tree node and are needed in every signature produced by this node.

---

## Verification — `verifyKES`

**Haskell reference:** `verifyKES` in `Sum.hs` / `Single.hs`

### Base case (depth 0)

```
Ed25519.verify(verKey, message, signature)
```

### Recursive case (depth d)

```
1. Parse signature → (childSig, sigVk0, sigVk1)

2. Check Merkle consistency:
       Blake2b-256(sigVk0 ‖ sigVk1) == verKey
   Reject if not equal.

3. Route to the active child:
   T = 2^(d-1)
   if period < T:
       verifyKES(sigVk0, message, period,   childSig, d-1)
   else:
       verifyKES(sigVk1, message, period-T, childSig, d-1)
```

Step 2 is the Merkle authentication step.  Without it, an attacker who knows
`vk0` or `vk1` could splice a valid child signature for a different subtree
into the outer signature.

---

## Tree structure (depth 3 example)

```
                    verKey (32 B)
                   = H(vk0 ‖ vk1)
                  /               \
           vk0 (32 B)          vk1 (32 B)
          = H(vk00‖vk01)      = H(vk10‖vk11)
           /         \           /          \
      vk00(32)    vk01(32)  vk10(32)    vk11(32)
      period 0    period 1  period 2    period 3
     (Ed25519)  (Ed25519) (Ed25519)  (Ed25519)
```

Period routing for depth 3:

| Period | Path |
|---|---|
| 0 | left → left → Ed25519 leaf |
| 1 | left → right → Ed25519 leaf |
| 2 | right → left → Ed25519 leaf |
| 3 | right → right → Ed25519 leaf |

---

## File map

| File | Contents |
|---|---|
| `constants.ts` | `sigSize`, `signKeySize`, `totalPeriods`, primitive size constants |
| `utils.ts` | `expandSeed`, `hashVKeys`, `concat`, `bytesEqual`, hex helpers |
| `kes.ts` | `genKeyKES`, `deriveVerKeyKES`, `signKES`, `updateKES`, `verifyKES` |
| `index.ts` | Public re-exports |
| `test.ts` | Self-contained test suite (51 assertions) |

---

## Dependencies

Both packages are pure JavaScript / WebAssembly and run in the browser with
no native bindings:

| Package | Version | Purpose |
|---|---|---|
| `@noble/curves` | `^1.6` | Ed25519 sign, verify, public key derivation |
| `@noble/hashes` | `^1.5` | Blake2b-256 hashing |

---

## Quick reference

```typescript
import { genKeyKES, signKES, verifyKES, updateKES } from './index.js';

const DEPTH = 6; // 64 periods — Cardano mainnet
const seed = crypto.getRandomValues(new Uint8Array(32));

// Generate
let { signKey, verKey } = genKeyKES(seed, DEPTH);

// Sign at period 0
const msg = new TextEncoder().encode('block header bytes here');
const sig0 = signKES(msg, 0, signKey, DEPTH);

// Verify
console.log(verifyKES(verKey, msg, 0, sig0, DEPTH)); // true

// Evolve to period 1 (old signKey material is gone)
signKey = updateKES(signKey, 0, DEPTH)!;
const sig1 = signKES(msg, 1, signKey, DEPTH);
console.log(verifyKES(verKey, msg, 1, sig1, DEPTH)); // true

// sig0 still verifiable against the same verKey
console.log(verifyKES(verKey, msg, 0, sig0, DEPTH)); // true
```
