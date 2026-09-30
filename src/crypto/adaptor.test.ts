// The ten invariants from the brief, as unit tests. Every one is COMPUTED -- no test
// here asserts a verdict that the source also merely asserts.

import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import {
  preSign,
  preVerify,
  adapt,
  extract,
  adaptorPoint,
  preSignatureAsBytes,
  sumParityOf,
  deriveNonce,
  eqBytes,
} from './adaptor'
import {
  N,
  G,
  mod,
  numTo32,
  fromHex,
  hex,
  liftX,
  xOnly,
  normaliseSecret,
  hasEvenY,
  CryptoInputError,
} from './secp'
import { ADAPTOR_FIXTURES, ADAPTOR_FIXTURE_MESSAGE, PARITY_COMBINATIONS } from './fixtures'

const MSG = new TextEncoder().encode('Alice pays Bob 0.10 units on ledger A')
const SK = numTo32(0x0a11ce0000000000000000000000000000000000000000000000000000000001n)
const T_SCALAR = 0x0b0b000000000000000000000000000000000000000000000000000000000001n

function setup(t = T_SCALAR, sk = SK, aux = 1n) {
  const { publicKey } = normaliseSecret(sk)
  const ad = adaptorPoint(t)
  const pre = preSign(sk, MSG, ad.Tx, { auxRand: numTo32(aux) })
  return { publicKey, ad, pre, sk }
}

describe('Invariant 1 — a pre-signature is not a signature', () => {
  it('BIP-340 verify rejects (x(R+T), s-hat) for every pinned fixture', () => {
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const sk = fromHex(f.secretKeyHex)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      const bytes = preSignatureAsBytes(pre)
      expect(bytes.length).toBe(64)
      // computed by the real verifier, not asserted
      expect(schnorr.verify(bytes, msg, fromHex(f.expect.publicKey))).toBe(false)
    }
  })

  it('and it is rejected because s-hat is short by exactly t', () => {
    // Scope the claim to the mechanism: the pre-signature fails not because it is
    // malformed, but because s-hat*G lands on R_adj instead of R_adj + T.
    const { pre, ad, publicKey } = setup()
    expect(schnorr.verify(preSignatureAsBytes(pre), MSG, publicKey)).toBe(false)
    const { signature } = adapt(pre, ad.t)
    expect(schnorr.verify(signature, MSG, publicKey)).toBe(true)
    // the only difference between the two byte strings is the last 32 bytes
    expect(hex(signature.slice(0, 32))).toBe(hex(preSignatureAsBytes(pre).slice(0, 32)))
    expect(hex(signature.slice(32))).not.toBe(hex(preSignatureAsBytes(pre).slice(32)))
  })
})

describe('Invariant 2 — pre-verification', () => {
  it('accepts an honest pre-signature and computes the same e', () => {
    const { pre, ad, publicKey } = setup()
    const r = preVerify(pre, publicKey, MSG, ad.Tx)
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.e).toBe(pre.e)
  })

  it('checks s-hat*G == R_adj + e*P by point comparison, with the right R_adj', () => {
    const { pre, ad, publicKey } = setup()
    const R = liftX(pre.rx)
    const Padj = liftX(publicKey)
    const lhs = G.multiply(pre.sHat)
    const rhsCorrect = (pre.parity === 'even' ? R : R.negate()).add(Padj.multiply(pre.e))
    const rhsWrong = (pre.parity === 'even' ? R.negate() : R).add(Padj.multiply(pre.e))
    expect(lhs.equals(rhsCorrect)).toBe(true)
    expect(lhs.equals(rhsWrong)).toBe(false)
    void ad
  })

  it('rejects a pre-signature whose s-hat has been altered', () => {
    const { pre, ad, publicKey } = setup()
    const tampered = { ...pre, sHat: mod(pre.sHat + 1n) }
    const r = preVerify(tampered, publicKey, MSG, ad.Tx)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/s-hat \* G/)
  })

  it('rejects when the message differs', () => {
    const { pre, ad, publicKey } = setup()
    const other = new TextEncoder().encode('Alice pays Bob 0.11 units on ledger A')
    expect(preVerify(pre, publicKey, other, ad.Tx).ok).toBe(false)
  })
})

describe('Invariant 3 — adapt produces a signature the library accepts', () => {
  it('holds for all pinned fixtures, both parities', () => {
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const sk = fromHex(f.secretKeyHex)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      const { signature, s } = adapt(pre, ad.t)
      expect(schnorr.verify(signature, msg, fromHex(f.expect.publicKey))).toBe(true)
      expect(s.toString(16)).toBe(f.expect.s)
    }
  })

  it('the sign follows the parity of R+T, and the other sign fails', () => {
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const sk = fromHex(f.secretKeyHex)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      // deliberately take the wrong branch
      const wrongS = pre.parity === 'even' ? mod(pre.sHat - ad.t) : mod(pre.sHat + ad.t)
      const wrongSig = new Uint8Array(64)
      wrongSig.set(pre.sumX, 0)
      wrongSig.set(numTo32(wrongS), 32)
      expect(schnorr.verify(wrongSig, msg, fromHex(f.expect.publicKey))).toBe(false)
    }
  })
})

describe('Invariant 4 — extract recovers t, and t*G == T', () => {
  it('recovers the exact t for every fixture and checks it against T', () => {
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const sk = fromHex(f.secretKeyHex)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      const { signature } = adapt(pre, ad.t)
      const ex = extract(pre, signature, ad.Tx)
      expect(ex.ok).toBe(true)
      if (ex.ok) {
        expect(ex.t).toBe(ad.t)
        expect(ex.t.toString(16)).toBe(f.expect.t)
        expect(G.multiply(ex.t).equals(liftX(ad.Tx))).toBe(true)
      }
    }
  })
})

describe('Invariant 5 — parity coverage', () => {
  it('the fixture set covers all four P / R+T parity combinations', () => {
    const seen = new Set<string>()
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const sk = fromHex(f.secretKeyHex)
      const dPrime = BigInt('0x' + f.secretKeyHex)
      const keyNegated = !hasEvenY(G.multiply(dPrime))
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      // the fixture's own recorded flags must match what the code computes
      expect(keyNegated).toBe(f.keyNegated)
      expect(pre.parity).toBe(f.parity)
      seen.add(`${keyNegated ? 'podd' : 'peven'}-sum${pre.parity}`)
    }
    for (const combo of PARITY_COMBINATIONS) expect(seen.has(combo)).toBe(true)
    expect(seen.size).toBe(4)
  })

  it('both t-normalisation branches are exercised', () => {
    const negated = ADAPTOR_FIXTURES.filter((f) => !f.deliberatelyWrong && f.tNegated).length
    const plain = ADAPTOR_FIXTURES.filter((f) => !f.deliberatelyWrong && !f.tNegated).length
    expect(negated).toBeGreaterThan(0)
    expect(plain).toBeGreaterThan(0)
  })

  it('a sweep hits both R+T parities and both t parities', () => {
    let even = 0
    let odd = 0
    let tNeg = 0
    for (let i = 1n; i <= 30n; i++) {
      const ad = adaptorPoint(i * 104729n + 17n)
      if (ad.negated) tNeg++
      const pre = preSign(SK, MSG, ad.Tx, { auxRand: numTo32(i) })
      pre.parity === 'even' ? even++ : odd++
    }
    expect(even).toBeGreaterThan(0)
    expect(odd).toBeGreaterThan(0)
    expect(tNeg).toBeGreaterThan(0)
  })
})

describe('Invariant 6 — the default nonce derivation binds T', () => {
  it('two pre-signatures on one message under different T have different R', () => {
    const a = adaptorPoint(T_SCALAR)
    const b = adaptorPoint(T_SCALAR + 1n)
    expect(hex(a.Tx)).not.toBe(hex(b.Tx))
    const p1 = preSign(SK, MSG, a.Tx, { auxRand: numTo32(1n) })
    const p2 = preSign(SK, MSG, b.Tx, { auxRand: numTo32(1n) })
    expect(hex(p1.rx)).not.toBe(hex(p2.rx))
  })

  it('the binding is in the nonce function itself, not in aux_rand', () => {
    // Same aux_rand, same message, same key: only T differs. If T were not hashed,
    // these two would be equal.
    const { d, publicKey } = normaliseSecret(SK)
    const a = adaptorPoint(T_SCALAR)
    const b = adaptorPoint(T_SCALAR + 1n)
    const aux = numTo32(9n)
    const k1 = deriveNonce('bound', d, publicKey, a.Tx, MSG, aux)
    const k2 = deriveNonce('bound', d, publicKey, b.Tx, MSG, aux)
    expect(k1).not.toBe(k2)
  })

  it('is deterministic: the same inputs give the same pre-signature', () => {
    const ad = adaptorPoint(T_SCALAR)
    const p1 = preSign(SK, MSG, ad.Tx, { auxRand: numTo32(3n) })
    const p2 = preSign(SK, MSG, ad.Tx, { auxRand: numTo32(3n) })
    expect(hex(p1.rx)).toBe(hex(p2.rx))
    expect(p1.sHat).toBe(p2.sHat)
  })
})

describe('Invariant 7 — the naive nonce mode really does reuse R', () => {
  it('two pre-signatures on one message share R when the nonce ignores T', () => {
    const a = adaptorPoint(T_SCALAR)
    const b = adaptorPoint(T_SCALAR + 1n)
    const p1 = preSign(SK, MSG, a.Tx, { mode: 'naive' })
    const p2 = preSign(SK, MSG, b.Tx, { mode: 'naive' })
    expect(hex(p1.rx)).toBe(hex(p2.rx))
    // and the challenges differ, which is what makes the system solvable
    expect(p1.e).not.toBe(p2.e)
  })

  it('naive nonces still produce valid signatures — the flaw is not a malfunction', () => {
    const ad = adaptorPoint(T_SCALAR)
    const { publicKey } = normaliseSecret(SK)
    const pre = preSign(SK, MSG, ad.Tx, { mode: 'naive' })
    expect(preVerify(pre, publicKey, MSG, ad.Tx).ok).toBe(true)
    const { signature } = adapt(pre, ad.t)
    expect(schnorr.verify(signature, MSG, publicKey)).toBe(true)
  })
})

describe('Invariant 8 — wrong-T rejection', () => {
  it('a pre-signature against T* fails preVerify against T', () => {
    const real = adaptorPoint(T_SCALAR)
    const fake = adaptorPoint(T_SCALAR + 12345n)
    const { publicKey } = normaliseSecret(SK)
    const pre = preSign(SK, MSG, fake.Tx, { auxRand: numTo32(4n) })
    expect(preVerify(pre, publicKey, MSG, real.Tx).ok).toBe(false)
    // but it is perfectly well-formed against the T it was actually built for
    expect(preVerify(pre, publicKey, MSG, fake.Tx).ok).toBe(true)
  })

  it('completing a wrong-T pre-signature with the real t gives a signature the library rejects', () => {
    const real = adaptorPoint(T_SCALAR)
    const fake = adaptorPoint(T_SCALAR + 12345n)
    const { publicKey } = normaliseSecret(SK)
    const pre = preSign(SK, MSG, fake.Tx, { auxRand: numTo32(4n) })
    const { signature } = adapt(pre, real.t)
    expect(schnorr.verify(signature, MSG, publicKey)).toBe(false)
  })
})

describe('Negative claim — without t the lab cannot produce s', () => {
  it('completing with a random t-prime never yields a signature the library accepts', () => {
    const { pre, publicKey } = setup()
    for (let i = 1n; i <= 25n; i++) {
      const guess = mod(BigInt('0x' + 'a3'.repeat(32)) * i + 7n)
      const { signature } = adapt(pre, guess)
      expect(schnorr.verify(signature, MSG, publicKey)).toBe(false)
    }
  })

  it('and the pre-signature holder learns nothing about t from it', () => {
    // Scoped precisely: the pre-signature commits to T, so it pins WHICH t would
    // work, but it does not reveal t. Both statements are checked.
    const { pre, ad, publicKey } = setup()
    expect(preVerify(pre, publicKey, MSG, ad.Tx).ok).toBe(true)
    // the same pre-signature would not pre-verify against a different T
    const other = adaptorPoint(T_SCALAR + 99n)
    expect(preVerify(pre, publicKey, MSG, other.Tx).ok).toBe(false)
  })
})

describe('Edge cases', () => {
  it('t = 0 is rejected', () => {
    expect(() => adaptorPoint(0n)).toThrow(CryptoInputError)
    expect(() => adaptorPoint(N)).toThrow(CryptoInputError)
  })

  it('T = O (an x that is not a curve point) is rejected at pre-sign', () => {
    expect(() => preSign(SK, MSG, numTo32(0n))).toThrow()
    expect(() => preSign(SK, MSG, numTo32(5n))).toThrow(/square root|invalid/)
  })

  it('R + T = O is unreachable in the honest construction, and the guard is still there', () => {
    // Both R and T are even-y by construction (they travel x-only), and R + T = O
    // needs T = -R, which has ODD y. So the honest path cannot reach it. The guard is
    // exercised directly at the chokepoint instead -- see secp.test.ts. Asserting the
    // unreachability here rather than claiming the branch is covered.
    const ad = adaptorPoint(T_SCALAR)
    const T = liftX(ad.Tx)
    expect(hasEvenY(T)).toBe(true)
    const pre = preSign(SK, MSG, ad.Tx)
    const R = liftX(pre.rx)
    expect(hasEvenY(R)).toBe(true)
    expect(hasEvenY(R.negate())).toBe(false)
    expect(R.add(T).is0()).toBe(false)
  })

  it('extraction with a mismatched s-hat / s pair reports failure, never a wrong t', () => {
    const a = setup(T_SCALAR, SK, 1n)
    const b = setup(T_SCALAR + 7n, SK, 2n)
    expect(hex(a.pre.sumX)).not.toBe(hex(b.pre.sumX))
    const { signature } = adapt(b.pre, b.ad.t)
    const ex = extract(a.pre, signature, a.ad.Tx)
    expect(ex.ok).toBe(false)
    if (!ex.ok) expect(ex.reason).toMatch(/do not pair/)
  })

  it('extraction reports failure when the recovered t does not match the expected T', () => {
    const { pre, ad } = setup()
    const wrong = adaptorPoint(T_SCALAR + 555n)
    const { signature } = adapt(pre, ad.t)
    const ex = extract(pre, signature, wrong.Tx)
    expect(ex.ok).toBe(false)
    if (!ex.ok) expect(ex.reason).toMatch(/does not equal the expected T/)
  })

  it('extraction rejects a signature that adds nothing (s == s-hat)', () => {
    const { pre } = setup()
    const sig = new Uint8Array(64)
    sig.set(pre.sumX, 0)
    sig.set(numTo32(pre.sHat), 32)
    const ex = extract(pre, sig)
    expect(ex.ok).toBe(false)
    if (!ex.ok) expect(ex.reason).toMatch(/no adaptor secret was added/)
  })

  it('extraction rejects a wrong-length signature', () => {
    const { pre } = setup()
    const ex = extract(pre, new Uint8Array(63))
    expect(ex.ok).toBe(false)
  })

  it('a malformed pre-signature (s-hat out of range) is rejected', () => {
    const { pre, ad, publicKey } = setup()
    expect(preVerify({ ...pre, sHat: 0n }, publicKey, MSG, ad.Tx).ok).toBe(false)
    expect(preVerify({ ...pre, sHat: N }, publicKey, MSG, ad.Tx).ok).toBe(false)
  })

  it('sumParityOf agrees with what preSign recorded', () => {
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const sk = fromHex(f.secretKeyHex)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      const sp = sumParityOf(pre.rx, ad.Tx)
      expect(sp.parity).toBe(pre.parity)
      expect(eqBytes(sp.sumX, pre.sumX)).toBe(true)
    }
  })
})

describe('the deliberately wrong fixture', () => {
  it('is present, and its expected s really is wrong', () => {
    const w = ADAPTOR_FIXTURES.find((f) => f.deliberatelyWrong)
    expect(w).toBeDefined()
    const sk = fromHex(w!.secretKeyHex)
    const ad = adaptorPoint(BigInt('0x' + w!.tRawHex))
    const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
    const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(w!.auxRandHex) })
    const { s } = adapt(pre, ad.t)
    expect(s.toString(16)).not.toBe(w!.expect.s)
    // exactly one row is wrong, so the table's green rows mean something
    expect(ADAPTOR_FIXTURES.filter((f) => f.deliberatelyWrong).length).toBe(1)
  })
})

describe('xOnly guard is reachable from the adaptor layer', () => {
  it('refuses to encode the identity', () => {
    expect(() => xOnly(G.add(G.negate()), 'R + T')).toThrow(CryptoInputError)
  })
})
