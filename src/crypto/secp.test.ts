// The chokepoint tests.
//
// The first block is the important one, and it exists because a precondition left as
// a comment is a precondition nobody enforces. It shows the RAW library call giving a
// plausible WRONG answer where the chokepoint throws. If a future version of
// @noble/curves makes the identity point fail closed on its own, these tests fail --
// which is the correct outcome: the chokepoint's reason for existing would have
// changed and someone should read it.

import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import {
  Point,
  N,
  P_FIELD,
  G,
  hasEvenY,
  xOnly,
  parityOf,
  mulG,
  liftX,
  assertScalar,
  invModN,
  numTo32,
  bytesToNum,
  fromHex,
  hex,
  challenge,
  normaliseSecret,
  CryptoInputError,
} from './secp'

describe('the fail-open precondition the chokepoint exists for', () => {
  it('RAW: the library reports x = 0 and an even y for the identity, without throwing', () => {
    // This is the wrong answer that looks right. Both of these are the raw library.
    expect(Point.ZERO.is0()).toBe(true)
    expect(Point.ZERO.x).toBe(0n)
    // hasEvenY is not on the published type, so reach it the way a caller would have
    // to: through a cast. That is itself part of the finding.
    const raw = Point.ZERO as unknown as { hasEvenY(): boolean }
    expect(raw.hasEvenY()).toBe(true)
  })

  it('RAW: byte serialisation of the identity DOES throw — the library is inconsistent', () => {
    // Worth pinning: it is the inconsistency, not the leniency, that makes this a
    // trap. A caller who serialises is protected; a caller who reads .x is not.
    expect(() => Point.ZERO.toBytes()).toThrow()
  })

  it('CHOKEPOINT: xOnly and parityOf refuse the identity instead', () => {
    expect(() => xOnly(Point.ZERO, 'R + T')).toThrow(CryptoInputError)
    expect(() => xOnly(Point.ZERO, 'R + T')).toThrow(/point at infinity/)
    expect(() => parityOf(Point.ZERO, 'R + T')).toThrow(CryptoInputError)
  })

  it('CHOKEPOINT: the two disagree on the same input, which is the whole point', () => {
    const identity = G.add(G.negate())
    expect(identity.is0()).toBe(true)
    expect(identity.x).toBe(0n) // raw: an answer
    let threw = false
    try {
      xOnly(identity, 'R + T')
    } catch {
      threw = true
    }
    expect(threw).toBe(true) // chokepoint: no answer
  })
})

describe('parity helper agrees with the library runtime method', () => {
  it('matches hasEvenY() across many points', () => {
    const raw = (p: unknown) => (p as { hasEvenY(): boolean }).hasEvenY()
    for (let i = 1n; i <= 60n; i++) {
      const p = G.multiply(i)
      expect(hasEvenY(p)).toBe(raw(p))
      expect(hasEvenY(p.negate())).toBe(raw(p.negate()))
    }
  })
})

describe('scalar range enforcement', () => {
  it('rejects t = 0 and t = n and t > n', () => {
    expect(() => assertScalar(0n, 't')).toThrow(/\[1, n-1\]/)
    expect(() => assertScalar(N, 't')).toThrow(CryptoInputError)
    expect(() => assertScalar(N + 5n, 't')).toThrow(CryptoInputError)
    expect(() => assertScalar(-1n, 't')).toThrow(CryptoInputError)
    expect(assertScalar(1n, 't')).toBe(1n)
    expect(assertScalar(N - 1n, 't')).toBe(N - 1n)
  })

  it('mulG refuses a zero scalar rather than returning the identity', () => {
    expect(() => mulG(0n, 't')).toThrow(CryptoInputError)
  })
})

describe('liftX', () => {
  it('returns the even-y point for a valid x', () => {
    const p = liftX(numTo32(G.x))
    expect(hasEvenY(p)).toBe(true)
    expect(p.x).toBe(G.x)
  })

  it('rejects x = 0 and x >= p', () => {
    expect(() => liftX(0n)).toThrow(CryptoInputError)
    expect(() => liftX(P_FIELD)).toThrow(CryptoInputError)
    expect(() => liftX(P_FIELD + 1n)).toThrow(CryptoInputError)
  })

  it('rejects an x with no point on the curve', () => {
    // Measured, not guessed: x = 1, 2, 3, 4, 6 and 8 ARE on secp256k1 (x^3+7 is a
    // quadratic residue there); 5, 7, 9, 10 and 11 are not.
    expect(() => liftX(5n)).toThrow(/square root/)
    expect(() => liftX(7n)).toThrow()
    expect(liftX(4n).x).toBe(4n)
  })
})

describe('byte and scalar helpers', () => {
  it('numTo32 and bytesToNum round-trip', () => {
    for (const v of [1n, 255n, 256n, N - 1n, 0x1234567890abcdefn]) {
      expect(bytesToNum(numTo32(v))).toBe(v)
    }
    expect(numTo32(0n).length).toBe(32)
  })

  it('fromHex rejects odd-length and non-hex input', () => {
    expect(() => fromHex('abc')).toThrow(/odd length/)
    expect(() => fromHex('zz')).toThrow(/hexadecimal/)
    expect(hex(fromHex('0xAB'))).toBe('ab')
  })

  it('invModN inverts and refuses 0', () => {
    expect((invModN(3n) * 3n) % N).toBe(1n)
    expect(() => invModN(0n)).toThrow(/not invertible/)
    expect(() => invModN(N)).toThrow(/not invertible/)
  })
})

describe('BIP-340 primitives match the library', () => {
  it('challenge() reproduces the library challenge implicit in a real signature', () => {
    // Independent route to the same number: take a published vector, recompute e from
    // its own bytes, and check s*G == R + e*P holds for the published signature. That
    // ties challenge() to the spec rather than to itself.
    const sk = fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF')
    const msg = fromHex('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89')
    const { publicKey, d } = normaliseSecret(sk)
    const sig = schnorr.sign(msg, sk, new Uint8Array(32))
    const rx = sig.slice(0, 32)
    const s = bytesToNum(sig.slice(32))
    const e = challenge(rx, publicKey, msg)
    const lhs = G.multiply(s)
    const rhs = liftX(rx).add(liftX(publicKey).multiply(e))
    expect(lhs.equals(rhs)).toBe(true)
    // and the key normalisation really is BIP-340's
    expect(G.multiply(d).x).toBe(bytesToNum(publicKey))
    expect(hasEvenY(G.multiply(d))).toBe(true)
  })

  it('normaliseSecret negates exactly when the raw key gives an odd-y point', () => {
    let negated = 0
    for (let i = 1n; i <= 30n; i++) {
      const sk = numTo32(i)
      const { d } = normaliseSecret(sk)
      const rawOdd = !hasEvenY(G.multiply(i))
      if (rawOdd) {
        expect(d).toBe(N - i)
        negated++
      } else {
        expect(d).toBe(i)
      }
    }
    expect(negated).toBeGreaterThan(0)
  })
})
