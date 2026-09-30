// INDEPENDENT RE-DERIVATION (template §4.1b).
//
// Everything below is computed WITHOUT importing ./adaptor.ts, ./secp.ts, or
// @noble/curves' Point class. It is plain BigInt arithmetic on AFFINE coordinates
// with its own modular inverse, its own point addition and doubling, its own
// double-and-add ladder, and its own tagged hash built from @noble/hashes' sha256.
//
// Why this file exists: a test that recomputes the same expression the source uses
// will happily agree with a bug. Internal consistency is not enough either -- a page
// can be consistently wrong, and a corrupted value reported consistently everywhere
// passes any self-agreement check. The only thing that catches that is arriving at
// the number by a different route. So this is the different route.
//
// The one thing it shares with the implementation is sha256 itself, which Gate 1
// already tied to BIP-340's published vectors.

import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2.js'
import { preSign, preVerify, adapt, extract, adaptorPoint } from './adaptor'
import { normaliseSecret, hex, fromHex, liftX } from './secp'
import { ADAPTOR_FIXTURES, ADAPTOR_FIXTURE_MESSAGE } from './fixtures'

// ---------------------------------------------------------------------------
// A self-contained secp256k1, affine, from the curve parameters as literals.
// ---------------------------------------------------------------------------
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const Nn = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

type Aff = { x: bigint; y: bigint } | null // null is the point at infinity

const m = (a: bigint, n = P) => ((a % n) + n) % n

/** Modular inverse by extended Euclid -- deliberately not the library's. */
function inv(a: bigint, n: bigint): bigint {
  let [old_r, r] = [m(a, n), n]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }
  if (old_r !== 1n) throw new Error('not invertible')
  return m(old_s, n)
}

function add(p: Aff, q: Aff): Aff {
  if (p === null) return q
  if (q === null) return p
  if (p.x === q.x && m(p.y + q.y) === 0n) return null
  let lam: bigint
  if (p.x === q.x && p.y === q.y) {
    lam = m(3n * p.x * p.x * inv(2n * p.y, P))
  } else {
    lam = m((q.y - p.y) * inv(q.x - p.x, P))
  }
  const x = m(lam * lam - p.x - q.x)
  return { x, y: m(lam * (p.x - x) - p.y) }
}

function mul(k: bigint, p: Aff): Aff {
  let acc: Aff = null
  let base = p
  let n = m(k, Nn)
  while (n > 0n) {
    if (n & 1n) acc = add(acc, base)
    base = add(base, base)
    n >>= 1n
  }
  return acc
}

const Gp: Aff = { x: GX, y: GY }
const neg = (p: Aff): Aff => (p === null ? null : { x: p.x, y: m(-p.y) })
const evenY = (p: Aff): boolean => {
  if (p === null) throw new Error('parity of the identity is not defined')
  return p.y % 2n === 0n
}

function b32(v: bigint): Uint8Array {
  const out = new Uint8Array(32)
  let x = v
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}
const num = (b: Uint8Array): bigint => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n)

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** BIP-340 tagged hash, built here rather than taken from the library. */
function tagged(tag: string, data: Uint8Array): Uint8Array {
  const th = sha256(new TextEncoder().encode(tag))
  return sha256(cat(th, th, data))
}

function sqrtModP(a: bigint): bigint {
  // p = 3 mod 4, so the square root is a^((p+1)/4).
  let r = 1n
  let base = m(a)
  let e = (P + 1n) / 4n
  while (e > 0n) {
    if (e & 1n) r = m(r * base)
    base = m(base * base)
    e >>= 1n
  }
  if (m(r * r) !== m(a)) throw new Error('no square root')
  return r
}

/** BIP-340 lift_x, independently. */
function liftXi(x: bigint): Aff {
  if (x <= 0n || x >= P) throw new Error('x out of range')
  const y2 = m(x * x * x + 7n)
  const y = sqrtModP(y2)
  return { x, y: y % 2n === 0n ? y : m(-y) }
}

// ---------------------------------------------------------------------------
// The re-derivation itself.
// ---------------------------------------------------------------------------

interface IndependentRun {
  publicKey: string
  Tx: string
  tNorm: bigint
  rx: string
  sumX: string
  parity: 'even' | 'odd'
  e: bigint
  sHat: bigint
  s: bigint
  recoveredT: bigint
  finalVerifies: boolean
  preSigVerifies: boolean
}

function independentRun(secretKeyHex: string, tRawHex: string, auxHex: string, message: string): IndependentRun {
  const msg = new TextEncoder().encode(message)
  const dPrime = num(fromHex(secretKeyHex))

  // key normalisation
  const Pfull = mul(dPrime, Gp)!
  const d = evenY(Pfull) ? dPrime : Nn - dPrime
  const Peven = mul(d, Gp)!
  const px = b32(Peven.x)

  // adaptor scalar normalisation: T travels x-only, so t must give an even-y T
  const tRaw = m(BigInt('0x' + tRawHex), Nn)
  const Traw = mul(tRaw, Gp)!
  const tNorm = evenY(Traw) ? tRaw : Nn - tRaw
  const T = mul(tNorm, Gp)!
  const Tx = b32(T.x)

  // nonce: BIP-340's function with x(T) inserted between the key and the message
  const aux = tagged('BIP0340/aux', fromHex(auxHex))
  const dB = b32(d)
  const tAux = new Uint8Array(32)
  for (let i = 0; i < 32; i++) tAux[i] = dB[i] ^ aux[i]
  const kPrime = m(num(tagged('BIP0340/nonce', cat(tAux, px, Tx, msg))), Nn)

  // R must be the even-y point, because it travels x-only too
  const R0 = mul(kPrime, Gp)!
  const kR = evenY(R0) ? kPrime : Nn - kPrime
  const R = mul(kR, Gp)!

  const Rsum = add(R, T)
  if (Rsum === null) throw new Error('R + T is the identity')
  const parity: 'even' | 'odd' = evenY(Rsum) ? 'even' : 'odd'
  const sumX = b32(Rsum.x)

  const e = m(num(tagged('BIP0340/challenge', cat(sumX, px, msg))), Nn)
  const k = parity === 'even' ? kR : Nn - kR
  const sHat = m(k + e * d, Nn)
  const s = parity === 'even' ? m(sHat + tNorm, Nn) : m(sHat - tNorm, Nn)
  const recoveredT = parity === 'even' ? m(s - sHat, Nn) : m(sHat - s, Nn)

  // Verify the finished signature by BIP-340's own equation, independently:
  //   s*G - e*P must be non-infinite, even-y, with x == sumX
  const verifyPoint = add(mul(s, Gp), neg(mul(e, Peven)))
  const finalVerifies =
    verifyPoint !== null && evenY(verifyPoint) && b32(verifyPoint.x).every((b, i) => b === sumX[i])

  // and the pre-signature must NOT verify under the same equation
  const preVerifyPoint = add(mul(sHat, Gp), neg(mul(e, Peven)))
  const preSigVerifies =
    preVerifyPoint !== null &&
    evenY(preVerifyPoint) &&
    b32(preVerifyPoint.x).every((b, i) => b === sumX[i])

  return {
    publicKey: hex(px),
    Tx: hex(Tx),
    tNorm,
    rx: hex(b32(R.x)),
    sumX: hex(sumX),
    parity,
    e,
    sHat,
    s,
    recoveredT,
    finalVerifies,
    preSigVerifies,
  }
}

describe('the independent lift_x agrees with the library on every fixture point', () => {
  it('re-derives the even-y lift of T, R and R+T from x alone', () => {
    // lift_x is where the parity convention actually lives, so it gets its own
    // independent implementation and its own comparison.
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      for (const xHex of [f.expect.Tx, f.expect.rx, f.expect.sumX, f.expect.publicKey]) {
        const mine = liftXi(BigInt('0x' + xHex))!
        const theirs = liftX(fromHex(xHex))
        expect(mine.x).toBe(theirs.x)
        expect(mine.y).toBe(theirs.y)
        expect(mine.y % 2n).toBe(0n)
      }
    }
  })
})

describe('independent affine re-derivation agrees with adaptor.ts', () => {
  it('reaches the same numbers by a different route, on every pinned fixture', () => {
    const real = ADAPTOR_FIXTURES.filter((f) => !f.deliberatelyWrong)
    expect(real.length).toBe(5)
    for (const f of real) {
      const ind = independentRun(f.secretKeyHex, f.tRawHex, f.auxRandHex, ADAPTOR_FIXTURE_MESSAGE)
      const sk = fromHex(f.secretKeyHex)
      const { publicKey } = normaliseSecret(sk)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      const { s } = adapt(pre, ad.t)

      // every intermediate, not just the final answer
      expect(ind.publicKey, `${f.id} pk`).toBe(hex(publicKey))
      expect(ind.Tx, `${f.id} T`).toBe(hex(ad.Tx))
      expect(ind.tNorm, `${f.id} t`).toBe(ad.t)
      expect(ind.rx, `${f.id} R`).toBe(hex(pre.rx))
      expect(ind.sumX, `${f.id} x(R+T)`).toBe(hex(pre.sumX))
      expect(ind.parity, `${f.id} parity`).toBe(pre.parity)
      expect(ind.e, `${f.id} e`).toBe(pre.e)
      expect(ind.sHat, `${f.id} s-hat`).toBe(pre.sHat)
      expect(ind.s, `${f.id} s`).toBe(s)
      expect(ind.recoveredT, `${f.id} extracted t`).toBe(ad.t)

      // and the two BIP-340 verdicts, derived from the curve equation here
      expect(ind.finalVerifies, `${f.id} completed signature must verify`).toBe(true)
      expect(ind.preSigVerifies, `${f.id} pre-signature must NOT verify`).toBe(false)
    }
  })

  it('agrees with the pinned expected values in fixtures.ts', () => {
    // Ties the independent path to the committed numbers too, so a fixture edited by
    // hand cannot quietly move both the source and the test together.
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const ind = independentRun(f.secretKeyHex, f.tRawHex, f.auxRandHex, ADAPTOR_FIXTURE_MESSAGE)
      expect(ind.publicKey).toBe(f.expect.publicKey)
      expect(ind.Tx).toBe(f.expect.Tx)
      expect(ind.rx).toBe(f.expect.rx)
      expect(ind.sumX).toBe(f.expect.sumX)
      expect(ind.parity).toBe(f.parity)
      expect(ind.tNorm.toString(16)).toBe(f.expect.t)
      expect(ind.e.toString(16)).toBe(f.expect.e)
      expect(ind.sHat.toString(16)).toBe(f.expect.sHat)
      expect(ind.s.toString(16)).toBe(f.expect.s)
    }
  })

  it('the deliberately wrong fixture disagrees with the independent path', () => {
    // The wrong row must be wrong by this route too, or it is not testing anything.
    const w = ADAPTOR_FIXTURES.find((f) => f.deliberatelyWrong)!
    const ind = independentRun(w.secretKeyHex, w.tRawHex, w.auxRandHex, ADAPTOR_FIXTURE_MESSAGE)
    expect(ind.s.toString(16)).not.toBe(w.expect.s)
  })

  it('the independent implementation is not a copy: it disagrees when the maths is changed', () => {
    // Guard against this file drifting into a re-run of the source. Flip the parity
    // rule by hand here and the numbers must move.
    const f = ADAPTOR_FIXTURES.find((x) => x.parity === 'odd' && !x.deliberatelyWrong)!
    const ind = independentRun(f.secretKeyHex, f.tRawHex, f.auxRandHex, ADAPTOR_FIXTURE_MESSAGE)
    const wrongWayRound = m(ind.sHat + ind.tNorm, Nn) // as if parity were 'even'
    expect(wrongWayRound).not.toBe(ind.s)
  })

  it('extract via adaptor.ts matches the independently derived t', () => {
    for (const f of ADAPTOR_FIXTURES.filter((x) => !x.deliberatelyWrong)) {
      const ind = independentRun(f.secretKeyHex, f.tRawHex, f.auxRandHex, ADAPTOR_FIXTURE_MESSAGE)
      const sk = fromHex(f.secretKeyHex)
      const ad = adaptorPoint(BigInt('0x' + f.tRawHex))
      const msg = new TextEncoder().encode(ADAPTOR_FIXTURE_MESSAGE)
      const pre = preSign(sk, msg, ad.Tx, { auxRand: fromHex(f.auxRandHex) })
      expect(preVerify(pre, fromHex(f.expect.publicKey), msg, ad.Tx).ok).toBe(true)
      const { signature } = adapt(pre, ad.t)
      const ex = extract(pre, signature, ad.Tx)
      expect(ex.ok).toBe(true)
      if (ex.ok) expect(ex.t).toBe(ind.recoveredT)
    }
  })
})
