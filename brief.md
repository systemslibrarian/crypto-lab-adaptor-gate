# BUILD BRIEF — crypto-lab-adaptor-gate

Binding spec: `CRYPTO-LAB-TEMPLATE.md` in this repo — a gitignored working copy of
`audits/_MASTER-TEMPLATE.md` from the catalog. This brief fills the template's NEW DEMO
BRIEF block and the seven §1 sections. Where this brief and the template disagree, the
template wins; report the conflict rather than resolving it silently.

*A previous revision named the file `_MASTER-TEMPLATE.md`. No such file is in this repo,
so the brief pointed at something that does not exist — corrected to the name actually on
disk.*

---

## NEW DEMO BRIEF

| Field | Value |
|---|---|
| **Repo name** | `crypto-lab-adaptor-gate` |
| **Short name (H1)** | Adaptor Gate |
| **Subtitle (spec label)** | BIP-340 Schnorr adaptor signatures · secp256k1 |
| **One-liner** | A pre-signature that becomes a real Schnorr signature only when a secret is added — and completing it hands that secret to whoever held the pre-signature. |
| **Concept to teach** | Adaptor signatures: the algebraic difference between a pre-signature and its completed signature *is* the adaptor secret. Atomic swaps and PTLCs are applications of that single fact, not separate topics. |
| **Primitives / spec** | BIP-340 Schnorr over secp256k1 (tagged-hash challenge, x-only keys, even-y nonce rule); Schnorr adaptor construction as formalized in Aumayr et al. (ASIACRYPT 2021) and re-proved in Gerhart et al. (EUROCRYPT 2024). |
| **`--accent`** | **ASSIGNED CENTRALLY — do not set a value in this repo.** *A previous revision proposed `#c2410c`. That is outside the catalog's four-colour rotation (`#35d6bb`, `#ffb84d`, `#ff6b7f`, `#9f88ff`), and four cards already carry off-palette accents with no recorded reason. Adding a fifth by default is how that becomes the norm. Leave `--accent` undefined here; central assignment picks it from the palette against the 4-, 2- and 1-column layouts.* |
| **Favicon** | **ASSIGNED CENTRALLY — do not set one.** *A previous revision proposed 🧩; that is already `crypto-lab-syndrome-hints`' favicon. Uniqueness is not enforced fleet-wide, but a collision should be a decision rather than an accident.* |
| **In scope** | Pre-sign / pre-verify / adapt / extract on real BIP-340 Schnorr; parity handling; nonce-reuse key recovery; malformed pre-signature rejection; one two-party cross-ledger swap walkthrough; one three-hop PTLC walkthrough showing per-hop decorrelation vs HTLC. |
| **Non-goals** | ECDSA adaptors; MuSig2 adaptors; any simulation presented as Bitcoin, Lightning or a real chain; scripts, mempools, fees, timelock enforcement mechanics; Monero/cross-curve swaps; lattice or post-quantum adaptors. |

---

## Thesis (the one invariant everything serves)

For a pre-signature `ŝ` and its completed signature `s` on the same nonce commitment,

```
s − ŝ ≡ ±t (mod n),   where T = t·G
```

with the sign fixed by the parity of `R + T` (see Invariants). Every act either builds this relation, uses it, or breaks it. The swap and PTLC acts are the *consequence*: publishing `s` on one ledger publishes `t` to anyone holding `ŝ`.

---

## §1 SCOPE

**Real (runs on the actual implementation):**
- secp256k1 arithmetic and BIP-340 hashing via a vetted library (`@noble/curves` `secp256k1` / `schnorr` — confirm current export names in the installed version).
- The lab's own adaptor layer: `preSign`, `preVerify`, `adapt`, `extract`, written on top of library point/scalar ops. The final signature it produces must verify under the **library's unmodified** BIP-340 `verify`.
- Nonce-reuse key recovery against the lab's own `preSign` when the naive-nonce toggle is on.

**Modeled (labelled as modeled in the UI):**
- Ledgers. Two deterministic state machines holding "coins" whose spend condition is "a valid BIP-340 signature under key P on this spend message." Label: *real deployments lock coins in a 2-of-2 joint key with a timelocked refund — see MuSig Gate; this lab models the lock so the adaptor math stays in view.*
- Timelocks. Shown as a step counter that enables a refund path; not a consensus mechanism.
- PTLC routing. Three hops, no channel state, no fees.

**Not implemented (state in the honesty panel):** ECDSA adaptors (need a different, more involved construction); MuSig2 adaptors; any network; real chain data.

---

## §1 SECURITY / CORRECTNESS INVARIANTS

Invariants beat features. Each is a claim in `e2e/claims.spec.ts`; each rendered verdict gets a §4.1c mutation.

1. **Pre-signature is not a signature.** For honest `(R, ŝ)` with `T ≠ O`, `(x(R+T), ŝ)` fails BIP-340 `verify`. Computed, not asserted.
2. **Pre-verification.** `ŝ·G == R_adj + e·P_even`, where `e = H_BIP0340/challenge(x(R+T) ‖ x(P) ‖ m)`, `R_adj = R` if `R+T` has even y else `−R`, and `P_even` is `P` with BIP-340 key negation applied.
3. **Adapt.** `s = ŝ + t` if `R+T` has even y, else `s = ŝ − t` (mod n). `(x(R+T), s)` passes the library's BIP-340 `verify`.
4. **Extract.** `t = ±(s − ŝ)` with the same parity rule; recovered `t` satisfies `t·G == T`. The UI compares recovered `t` against the true `t` by computation.
5. **Parity coverage.** Both parity branches are exercised by fixtures (see Edge Cases); a lab that only ever hits the even branch fails its claims.
6. **Nonce binding.** Default nonce derivation binds `T` (e.g. BIP-340 nonce function with `T` mixed into the aux/message input — document the exact construction). Two pre-signatures on the same `m` under different `T` must have different `R`.
7. **Nonce-reuse break is real.** With the naive toggle (nonce derived from `m` only), two pre-signatures on the same `m` under `T₁ ≠ T₂` share `R`; recover `d = (ŝ₁ − ŝ₂)/(e₁ − e₂)` (with parity adjustments) and prove it by signing a fresh message that the library verifies under `P`.
8. **Wrong-T rejection.** A pre-signature built against `T* ≠ T` fails `preVerify(…, T)`. The swap act shows the loss that occurs if a party skips pre-verification.
9. **Swap atomicity (model level).** In the swap act, Bob's claim on ledger A is possible iff Alice's claim on ledger B has been published; the `t` Bob uses is the value he extracted, read from ledger B's state — never passed from Alice's panel.
10. **PTLC decorrelation.** Per-hop adaptor points differ; the HTLC contrast shows the same hash on every hop. Both are computed from the same run.

---

## §1 ARCHITECTURE

- Single-page Vite/TS build per template; GitHub Pages; no backend.
- `src/crypto/adaptor.ts` — the only file that implements adaptor logic. Pure functions over bytes/bigints.
- `src/crypto/ledger.ts` — modeled ledgers; they call the library's `verify`, never `adaptor.ts`.
- `src/crypto/attacks.ts` — nonce-reuse recovery, wrong-T demo. Attacks call the same `adaptor.ts` functions the honest path calls; no parallel "attack-mode" implementation.
- Verdicts are derived from function outputs at render time; no string literal says an attack succeeded.

**Vectors:**
- BIP-340 official vectors at `bip-0340/test-vectors.csv` in the `bitcoin/bips` repository —
  **19 data rows, and the shape of them was measured rather than assumed:**
    - Message lengths are 32 bytes on rows 0-14, then 0, 1, 17 and 100 bytes on rows 15-18.
      **Exactly ONE row (18, at 100 bytes) crosses a 64-byte SHA-256 block.** Keep it, and treat
      it as the only multi-block coverage the standard gives you — if you drop it you lose that
      path entirely. Consider generating a second multi-block case and cross-checking it against
      an independent implementation.
    - **Only 8 of the 19 rows are signable** (rows 0-3 and 15-18 carry a secret key and
      `aux_rand`); the other 11 are verify-only negative rows. So the pre-verify-then-adapt round
      trip runs on those 8, and the remaining 11 exercise `verify` rejection only. Say which is
      which in the UI rather than implying all 19 round-trip.
- **There are no standardized single-signer Schnorr-adaptor test vectors. This was checked, not
  assumed:** neither BIP-327 (MuSig2) nor secp256k1-zkp publishes any. So the "if not" branch
  applies and is settled — do not re-litigate it, and do **not** label any derived fixture
  "official." Pin deterministic fixtures and cross-check them with an independent re-derivation in the test (separate BigInt affine-coordinate path that does not import `adaptor.ts`) per §4.1b.

---

## §1 UI

Plain-language intro before any hex. Acts:

1. **Lock** — Alice picks secret `t`; `T = tG` shown. Plain words: "T is a padlock anyone can see; t is the key."
2. **Pre-sign** — Bob pre-signs a message against `T`. Show that BIP-340 `verify` rejects `(x(R+T), ŝ)` (Invariant 1) and `preVerify` accepts.
3. **Complete** — enter `t`, get `s`, library `verify` accepts. Headline visual: `s − ŝ` rendered next to `t`, with a computed equality badge.
4. **Extract** — given only `ŝ` (held earlier) and the published `s`, recover `t`. This is the headline.
5. **Swap** — two modeled ledgers. Alice ↔ Bob exchange pre-signatures against the same `T`; Alice claims on B by publishing `s_B`; Bob reads `s_B` from ledger B state, extracts `t`, claims on A. A "skip pre-verify" toggle shows the wrong-T loss.
6. **PTLC (3 hops)** — Alice → Bob → Carol. Side-by-side HTLC strip showing one hash repeated across hops vs PTLC points that differ per hop; extraction propagates backward hop by hop.
7. **Break it** — naive-nonce toggle → key recovery → forged fresh signature verified by the library.
8. **Honesty panel** — real / modeled / not implemented; threat model (below).

Cross-links (verify slugs against the catalog before linking; do not guess): Schnorr lab → MuSig/FROST labs → Bitcoin Script / wallet labs. The lab should not reteach Schnorr; one sentence plus link.

**Threat model shown in UI:** signer is honest-but-may-reuse-nonces (Break it); counterparty may send malformed pre-signatures (Invariant 8); ledgers are modeled as honest and live; security of honest pre-signatures rests on discrete log in the random-oracle model (Gerhart et al. 2024 re-prove Schnorr adaptors under their strengthened definitions).

---

## §1 VISUAL SEMANTICS

- `t` and everything derived from it share one colour; pre-signature `ŝ` a second; final `s` a third. The difference strip `s − ŝ` uses `t`'s colour only when the computed equality holds.
- Never draw a completed signature before `t` is supplied. Never draw the swap as simultaneous — it is ordered, and the order is the lesson.
- No decorative motion.

---

## §1 EDGE CASES

- `R + T` odd-y (must be hit by a pinned fixture; the negation path is the classic bug).
- `P` odd-y (BIP-340 key negation) combined with each nonce parity — all four combinations fixtured.
- `T = O` or `R + T = O` → reject with explanation.
- `t = 0` → reject.
- Extraction with mismatched `ŝ` / `s` (different `R`) → reports failure, never returns a wrong `t` silently.
- Nonce reuse with `e₁ = e₂` (only if `T₁ = T₂`) → recovery correctly reports "not recoverable from these two."

---

## §1 EXTENSION SEAMS

- MuSig2 adaptor (2-of-2 lock made real) — link to MuSig lab rather than building here.
- ECDSA adaptors — separate lab if ever.
- Post-quantum adaptor constructions — note existence only.

---


---

## HERO — three roles, and they must say different things

The template (§3.1) requires the hero to carry three distinct texts, and the usual failure
is making the description and the why-box restate each other. Write them so each answers a
different question:

- **Subtitle** — the spec label only. Not a sentence. (See the NEW DEMO BRIEF row above.)
- **Description** — one sentence on WHAT you will see and do here, mechanism-first.
- **Why it matters** — two or three sentences on the STAKES. Never a paraphrase of the
  description.

## BUILD DISCIPLINE — gates before UI, and the traps that have actually cost time

These are not style notes. Each one is a failure that happened while building a sibling lab
in this fleet, and each cost more to diagnose than it costs to avoid.

**1. Verify the library before you trust it, and record what you verified against.**
Every dependency that does cryptography gets checked against a PUBLISHED vector before any
lab code is written on top of it — not its own README's claim, a vector from the spec or a
standards body. Pin that check as a test so it keeps holding. A wrapper that is subtly wrong
looks exactly like a lab that is subtly wrong, and you will look for the bug in your own code.

**2. A vendored or wrapped primitive can have a silent-wrong-answer precondition.**
A sibling lab's vendored pairing engine required both arguments in affine form and returned
a plausible-looking wrong field element otherwise, with no throw — while the multiply
functions it was paired with returned projective points. Two false test failures were chased
before the cause was found. If you wrap anything, put ONE chokepoint in front of it that
normalises or validates, and write a test that shows the raw call giving a different answer.
Do not leave the precondition as a comment.

**3. The preview port is not a free choice.** Vite's default is 4173 and labs across this
fleet collide on it. Playwright's `reuseExistingServer` sees *something* answering and hands
the suites a DIFFERENT lab's build, so the gates run green or red against a page this repo
never produced. Pick a port no sibling `playwright.config.ts` claims, and name it in exactly
one constant that `baseURL`, `webServer.command` and `webServer.url` all read.

**4. A checker only ever seen agreeing cannot be trusted.** If every fixture passes, a
mutation that forces the comparison true changes nothing observable and your suite proves
nothing. Ship a deliberately WRONG fixture alongside the real ones, render it as a row like
any other, and assert it is reported as failing. And print BOTH the computed and the expected
value on every row, always — not only when they differ. A badge that is the only evidence for
its own claim is unfalsifiable from the page.

**5. Mutation hygiene (§4.1c), stated because it went wrong.** Commit the real work BEFORE
mutating. One mutation at a time, restored immediately. Never stage or commit while a
mutation harness is running — a background harness held a file mid-mutation during a `git
add` and the mutation shipped; CI caught it, but only because the claims suite runs before
the Pages artifact uploads. And a mutation that leaves every test green proves nothing about
the tests: check whether it actually changed rendered output before recording it as a miss.

**6. Scope every claim to the mechanism that produces it.** The largest defect class here is
a right conclusion reached through a wrong causal chain. Before shipping any sentence about
what an attack or a limitation shows, write down the exact inputs that are wrong, which check
passes, and why — then check the sentence against that. "X does not prove Y" is almost always
too broad; "X does not pin WHICH Y, only that both sides agreed on one" is usually the true
statement.

## Claims & CI (reference existing mechanisms; do not invent new ones)

- `e2e/claims.spec.ts` (§4.1b): Invariants 1–10 as claims, including the independent BigInt re-derivation of adapt/extract.
- §4.1c: one mutation per rendered verdict (flip parity rule, drop `T` from nonce derivation, swap `+t`/`−t`, feed extraction the wrong `ŝ`) — each must turn a claim red.
- §4.1d negative claims: "a pre-signature alone does not verify"; "without `t`, the lab cannot produce `s`" (tested by attempting completion with random `t'` and asserting library rejection).
- Functional browser tests (Playwright) walking every act end to end, plus the §4 axe/WCAG gate.

## Catalog checks for the agent (do not assert; run and report)

- Sweep the catalog and the lab clones for existing adaptor-signature coverage and REPORT what you find. Do not write "first", "only" or "no other lab" into shipped copy on the strength of a sweep — state the coverage you found, or say the sweep was clean and name what it searched. Include `adaptor`, `pre-signature`, `presig`, `scriptless`, `PTLC`, `atomic swap`, and use separator classes that include Unicode en/em dashes.
- Confirm category placement (SIGNATURES expected) and report the neighbouring cards for the accent check.

## Primary sources (verified Sep 29, 2026)

- BIP-340, Schnorr Signatures for secp256k1 — spec and `test-vectors.csv`.
- L. Aumayr, O. Ersoy, A. Erwig, S. Faust, K. Hostáková, M. Maffei, P. Moreno-Sanchez, S. Riahi,
  *Generalized Channels from Limited Blockchain Scripts and Adaptor Signatures*, ASIACRYPT 2021,
  LNCS pp. 635-664, DOI 10.1007/978-3-030-92075-3_22; ePrint 2020/476 — the game-based security
  definitions the field standardised on. **Described by its own authors** as the first standalone
  formalization; do not assert that as a fact. L. Fournier, *One-Time Verifiably Encrypted
  Signatures A.K.A. Adaptor Signatures* (2019) claims the same ground and predates it
  and Aumayr et al. cite it as concurrent and weaker, while Gerhart et al. do not cite it at all.
  Priority is contested; report both rather than adjudicating.
- P. Gerhart, D. Schröder, P. Soni, S. A. K. Thyagarajan, *Foundations of Adaptor Signatures*,
  EUROCRYPT 2024, LNCS 14652 (Part II), pp. 161-189, DOI 10.1007/978-3-031-58723-8_6;
  ePrint 2024/1809 — strengthened definitions, Schnorr adaptors re-proved. *The venue/ePrint
  pairing looks wrong and is not: the ePrint was posted 2024-11-05, five months AFTER the
  conference (Zurich, 26-30 May 2024), as a late archival posting. Checked four ways; leave it.*
- A. Poelstra, *Scriptless Scripts*, slides, MIT Bitcoin Expo, 4 March 2017 —
  `https://download.wpsoftware.net/bitcoin/wizardry/mw-slides/2017-03-mit-bitcoin-expo/slides.pdf`
  (host is `.net`, not `.com`). The construction itself first appeared in Poelstra,
  *Lightning in Scriptless Scripts*, mimblewimble mailing list, 20 March 2017. Background only,
  never cited as a spec.