# Vector provenance

## `bip340-test-vectors.csv`

- **Source:** `bip-0340/test-vectors.csv` in the `bitcoin/bips` repository.
- **Fetched:** 2026-09-29 from
  `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv`
- **sha256 of the file as vendored:**
  `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`
- **Shape, measured rather than assumed** (see `src/crypto/bip340-kat.test.ts`, which
  re-measures all of this on every run so a re-fetch that changes the file fails loudly):
  - 19 data rows.
  - Message lengths: 32 bytes on rows 0-14, then 0, 1, 17 and 100 bytes on rows 15-18.
  - **8 rows are signable** (0-3 and 15-18): they carry a secret key and `aux_rand`, so
    the deterministic signature is reproducible byte-for-byte. The pre-verify /
    adapt / extract round trip runs on these 8.
  - **11 rows are verify-only.** Of those, **1 is a positive row** (row 4, expected
    result TRUE, public key and signature only) and **10 are negative rows**
    (rows 5-14). The UI labels all three classes separately rather than implying that
    all 19 round-trip.
  - Row 18 (100-byte message) is the only row whose message length pushes the
    challenge tagged-hash into a fourth SHA-256 compression block. See the note below.

### On "the only row that crosses a block boundary"

The build brief says row 18 is the only row that crosses a 64-byte SHA-256 block. The
conclusion is right and the reason as stated is not, so it is recorded precisely here.

BIP-340's challenge is a tagged hash, `SHA256(SHA256(tag) || SHA256(tag) || r || pk || m)`,
so its input is `64 + 32 + 32 + len(m)` = `128 + len(m)` bytes. 128 bytes is already two
full blocks, so *every* row's challenge hash spans multiple blocks -- there is no row
that fits in one. Counting compression blocks after padding, `ceil((128 + len(m) + 9) / 64)`:

| row(s) | len(m) | hash input | blocks |
|---|---|---|---|
| 15 | 0 | 128 | 3 |
| 16 | 1 | 129 | 3 |
| 17 | 17 | 145 | 3 |
| 0-14 | 32 | 160 | 3 |
| **18** | **100** | **228** | **4** |

So row 18 is the only row that reaches a fourth block, i.e. the only message-length-driven
extra-block coverage the standard offers. Keep it for that reason. Dropping it would lose
the path; keeping it under the wrong description would invite someone to "fix" the wrong
thing later.
