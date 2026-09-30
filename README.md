# Adaptor Gate

**BIP-340 Schnorr adaptor signatures · secp256k1**

A pre-signature that becomes a real Schnorr signature only when a secret is added — and
completing it hands that secret to whoever held the pre-signature.

**[Live demo](https://systemslibrarian.github.io/crypto-lab-adaptor-gate/)**

---

## What It Is

An adaptor signature is a signature with a piece missing. A signer produces a
**pre-signature** that is provably bound to a public point `T`, and it is *not* a valid
signature — BIP-340's own verifier rejects it. Whoever knows the secret `t` behind that
point (`T = t·G`) can add `t` and turn it into a signature the real verifier accepts.

The one fact this lab exists to teach is what follows from that. For a pre-signature `ŝ`
and its completed signature `s` on the same nonce commitment:

```
s − ŝ ≡ ±t  (mod n),   where T = t·G
```

with the sign fixed by the parity of `R + T`. So completing the signature and publishing
the secret are **the same act**. Atomic swaps and PTLCs are applications of that single
fact rather than separate topics, and both are built here on top of the same four
functions.

**The exact primitives.** BIP-340 Schnorr over secp256k1 — tagged-hash challenge, x-only
keys, the even-y nonce rule — via `@noble/curves` 2.4.0. The adaptor layer
(`preSign`, `preVerify`, `adapt`, `extract`) is this lab's own code written on top of the
library's point and scalar operations, and the signature it finally produces is verified
by the **library's unmodified BIP-340 `verify`**, never by this lab. The construction is
the one formalized in Aumayr et al. (ASIACRYPT 2021) and re-proved under strengthened
definitions in Gerhart et al. (EUROCRYPT 2024).

**The security model.** Security of an honest pre-signature rests on the discrete
logarithm problem in the random-oracle model. The threat model shown in-page: the signer
is honest but may reuse nonces; the counterparty may send malformed or wrong-`T`
pre-signatures; the modeled ledgers are assumed honest and live.

**Not production crypto — a teaching demo.** Keys come from values typed into a text box,
nothing is constant-time, nothing is persisted, and no part of this should be used to move
anything of value.

### What is real, and what is modeled

| | |
|---|---|
| **Real** | secp256k1 arithmetic and BIP-340 tagged hashing, checked against BIP-340's own 19 published vectors *before* any lab code was built on the library. |
| **Real** | The adaptor layer itself, and the final signature verified by the library's unmodified `verify`. |
| **Real** | Nonce-reuse key recovery, run against this lab's own `preSign`, proved by signing a fresh message the library then accepts. |
| **Modeled** | The ledgers — deterministic state machines whose spend condition is "a valid BIP-340 signature under key `P` over this message". The signature check is real; there is no chain, script, mempool or fee. A real deployment would lock coins in a 2-of-2 joint key with a timelocked refund (see MuSig Gate); this lab models the lock so the adaptor arithmetic stays in view. |
| **Modeled** | Timelocks — a step counter enabling a refund path, not a consensus mechanism. |
| **Modeled** | PTLC routing — three hops, real pre-signatures, no channel state, fees, network or onion routing. |
| **Not built** | ECDSA adaptors (a different, more involved construction), MuSig2 adaptors, any multi-party signing, any network or real chain data, post-quantum adaptor constructions. |

### What it does NOT prove

- A pre-signature does not reveal `t`. What it *does* do is pin **which** `t` would
  complete it — a commitment to the secret, not a leak of it.
- **A correct extraction does not mean a swap was safe.** Extraction can return exactly
  the right secret while the counterparty's pre-signature committed to a different point,
  and no check on the page raises a failure code for that — there is no code to raise. The
  absence of one *is* the exhibit. Only pre-verifying against the `T` the payment names
  detects it. Exhibit 2 drives that state and shows every check passing while the funds
  are gone.
- Per-hop decorrelation is an algebraic property of the identifiers only. It does not make
  a routed payment private: amounts, timing and topology all still correlate and none are
  modeled.
- Passing this lab's fixtures establishes no conformance. There are no official adaptor
  vectors to conform to.

## Exhibits

1. **The Relation** — the headline, in four steps. Lock a secret behind a point; pre-sign
   against it and watch BIP-340 `verify` reject the pre-signature while pre-verification
   accepts it; supply `t` and get a signature the library accepts; then recover `t` from
   nothing but the pre-signature and the published signature. The difference strip renders
   `s − ŝ` beside the true `t` with a computed equality badge — **supply a wrong `t` and it
   goes red**, which is what makes the green state evidence rather than decoration.
2. **Cross-Ledger Swap** — two modeled ledgers, in order, because the order is the lesson.
   Alice completes Bob's pre-signature and publishes; Bob reads those bytes *off ledger B*
   and extracts `t`; Bob claims on ledger A. Two toggles: Bob skips pre-verification, and
   Alice pre-signs against a different `T`. Each alone is harmless; together they are a
   total loss, with every check Bob ran still reporting success.
3. **PTLC vs HTLC** — three hops, both strips computed from one run. Three distinct adaptor
   points against one repeated hash. Settlement propagates backward hop by hop, and each
   intermediary derives its own secret by adding the blinding scalar it was handed.
4. **Break It** — the naive-nonce toggle makes two pre-signatures on one message share a
   nonce; the key falls out and a forged signature on a fresh message is accepted by the
   library. A second toggle shows the edge case where the nonce *is* reused and the key is
   still not recoverable.
5. **Vectors & Fixtures** — BIP-340's 19 official vectors run live, and this lab's pinned
   adaptor fixtures. Every row prints the computed value beside the expected one whether or
   not they match, and **one fixture row is wrong on purpose** and reports failure.
6. **What This Is & Isn't** — real / modeled / not built, the threat model, the negative
   claims, and the sources.

## When to Use It

- Use it to see why completing an adaptor signature and publishing a secret are the same
  act, because the subtraction runs on screen against the real `t` rather than being
  asserted.
- Use it to understand atomic swaps without a chain in the way, because the ledgers are
  reduced to the one rule that matters and the ordering is driven rather than drawn.
- Use it to see why pre-verification is not optional, because the loss it prevents is
  reachable through two checkboxes and every other check still reports success.
- Use it to see how PTLCs decorrelate a route, because both the point strip and the hash
  strip are derived from the same payment in the same run.
- **Do NOT use it** to move funds, to generate keys, or as a reference implementation of
  adaptor signatures. It is a teaching demo, it is not constant-time, and its ledgers are
  models.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-adaptor-gate/**

Pre-sign a message and watch the real verifier refuse the pre-signature; complete it with a
wrong `t` and watch the headline badge go red and the verifier refuse the result; complete
it with the real one and read the secret back out; run the swap honestly and then break it
two ways; compare per-hop PTLC points against a repeated HTLC hash; recover a private key
from two pre-signatures that reused a nonce and see the forged signature accepted; and read
all 19 BIP-340 vectors and the fixture table, including the row that fails on purpose.

## What Can Go Wrong

- **The parity of `R + T` fixes a sign, and getting it wrong is the classic adaptor bug.**
  `s = ŝ + t` when `R + T` has even y and `s = ŝ − t` when it has odd y. Both branches are
  exercised by pinned fixtures; a lab that only ever hits the even branch fails its claims.
- **`R` and `T` both travel x-only**, so both denote the even-y point and both the nonce
  scalar and the adaptor scalar must be normalised to match. Skipping the normalisation on
  `R` produces a pre-signature that pre-verifies against the negation of the point it was
  built from — caught here by a test during the build.
- **A nonce that does not bind `T`** lets two pre-signatures on one message share `R`, and
  the key falls out. Note the precision: nonce reuse alone is not sufficient. The two
  challenges must also differ, which means the two `T` must differ; reuse under a single `T`
  yields `e₁ = e₂` and recovers nothing.
- **Recovery is two equations, not one.** When both `R + T` parities agree the nonce
  cancels in the difference; when they differ it cancels in the **sum**. A recovery
  implementing only the difference branch silently fails on half its inputs.
- **A wrong-`T` pre-signature is not malformed.** It pre-verifies perfectly against the
  point it was actually built for. Nothing detects it except pre-verifying against the `T`
  the payment names.
- **The library has a fail-open precondition at the identity point.** `Point.ZERO.toBytes()`
  throws, but `Point.ZERO.x` returns `0n` and `hasEvenY()` returns `true`, both silently.
  A layer that reads `x(R+T)` or its parity straight off the library would compute a
  well-formed-looking challenge over `x = 0` for the degenerate case. This lab puts one
  chokepoint in front of the library that refuses the identity, and a test asserts the raw
  calls giving those wrong answers beside the chokepoint refusing them.

## Real-World Usage

Adaptor signatures are the basis of **scriptless scripts**: conditions enforced by
signature algebra rather than by on-chain script. In practice that means cross-chain
atomic swaps, where one party's claim publishes the secret the other needs, and
**PTLCs** — the point-based replacement for Lightning's HTLCs, which removes the shared
payment hash that makes every hop on a route linkable. The construction is also used for
discreet log contracts and for atomic multi-path payments. Bitcoin's Taproot activation
(BIP-340 Schnorr) is what made the single-signer form practical on-chain; the joint-key
lock a real deployment would use is MuSig2 territory.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-adaptor-gate.git
cd crypto-lab-adaptor-gate
npm install
npm run dev
```

No environment variables are required. To run the browser gates you also need the
Playwright browsers: `npx playwright install --with-deps chromium firefox webkit`.

## Related Demos

- [crypto-lab-schnorr-forge](https://systemslibrarian.github.io/crypto-lab-schnorr-forge/) —
  BIP-340 Schnorr itself. **Start here if `s = k + e·d` is unfamiliar**; this lab assumes it.
- [crypto-lab-musig-gate](https://systemslibrarian.github.io/crypto-lab-musig-gate/) — the
  2-of-2 joint key this lab models as a single-key lock.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) —
  threshold signing, the t-of-n direction.
- [crypto-lab-bitcoin-script](https://systemslibrarian.github.io/crypto-lab-bitcoin-script/) —
  the scripted spending conditions scriptless scripts replace.
- [crypto-lab-bitcoin-wallet](https://systemslibrarian.github.io/crypto-lab-bitcoin-wallet/) —
  keys and addresses.

## Build & Verify

```bash
npm run build       # tsc --noEmit && vite build
npm test            # 114 unit tests across 7 files (Vitest)
npm run test:a11y   # 77 browser tests: axe WCAG gate, claims suite, flows in 4 browsers
```

**Unit tests — 114, all passing.**

| suite | what it pins |
|---|---|
| `src/crypto/bip340-kat.test.ts` | **The library gate.** All 19 rows of BIP-340's `test-vectors.csv`: verify results on all 19, byte-exact deterministic signatures on the 8 signable rows. Also pins the vector file's own sha256 and re-measures its shape. |
| `src/crypto/secp.test.ts` | The chokepoint, including the raw library calls giving fail-open answers at the identity where the chokepoint throws. |
| `src/crypto/adaptor.test.ts` | Invariants 1–8 and every edge case, over fixtures covering all four `P`/`R+T` parity combinations. |
| `src/crypto/adaptor-independent.test.ts` | **The independent re-derivation.** A self-contained affine BigInt secp256k1 — its own modular inverse, point addition, ladder, `lift_x` and tagged hash — that imports neither `adaptor.ts` nor the library's `Point`, and agrees on every intermediate value. |
| `src/crypto/attacks.test.ts` | Nonce-reuse recovery on both algebraic branches, with a test proving the sum branch is load-bearing. |
| `src/crypto/swap.test.ts` | Swap atomicity, the ledger's real signature checks, and the wrong-`T` loss. |
| `src/crypto/ptlc.test.ts` | Per-hop decorrelation, backward settlement, and the blinding being load-bearing. |

**KAT files.** `src/vectors/bip340-test-vectors.csv`, vendored byte-for-byte from
`bip-0340/test-vectors.csv` in `bitcoin/bips` with its provenance, sha256 and measured
shape recorded in `src/vectors/PROVENANCE.md`. There are **no official single-signer
Schnorr adaptor vectors** — neither BIP-327 nor secp256k1-zkp publishes any — so this
lab's adaptor fixtures in `src/crypto/fixtures.ts` are self-derived, are never labelled
official, and are guarded by the independent re-derivation above.

**Browser gates — 77 tests.**

- `e2e/a11y.spec.ts` — the axe-core WCAG 2.1 A/AA gate, run against the **production
  build** at desktop and 380px. Zero violations and zero `incomplete` findings; contrast is
  additionally computed arithmetically, and the non-text (1.4.11) baseline is **empty**,
  measured for this lab rather than inherited.
- `e2e/claims.spec.ts` — 31 claims that the page tells the truth: cross-checks between
  surfaces, parts-sum-to-whole over the vector classes and fixture rows, and independent
  re-derivations evaluated in the browser with arithmetic sharing no code with the bundle.
  Includes the negative-claim fixture (every check green, funds gone, the limitation on
  screen).
- `e2e/flows.spec.ts` — functional walkthroughs of every exhibit in Chromium, Firefox,
  WebKit and a mobile viewport.

Every rendered verdict has a matching source mutation recorded in `e2e/claims.spec.ts`,
and each was run: the mutation was applied, the build confirmed to still succeed, the
bundle hash confirmed to move, and the owning claim confirmed to fail.

The CI workflow gates the Pages deploy on **all** of it — `npm test`, the build, then the
full Playwright run — so a broken proof, a broken claim or an accessibility regression
blocks a publish.

## Performance

Everything runs in the browser on a single 256-bit curve; the whole unit suite takes about
two seconds, and the heaviest page operation is the fixture table, which performs five
full pre-sign/adapt/extract round trips plus 19 vector verifications on render.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
