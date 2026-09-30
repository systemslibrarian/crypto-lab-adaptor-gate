// THE CHOKEPOINT.
//
// Every point and scalar entering the adaptor layer passes through this file, and
// nothing outside it touches @noble/curves' Point class directly. That is not
// tidiness; it is a response to a measured fail-open precondition in the library.
//
// Measured against @noble/curves 2.4.0 (see secp.test.ts, which asserts these raw
// answers so a version bump that changes them fails loudly):
//
//   Point.ZERO.toBytes()    -> THROWS "bad point: ZERO"     (fail-closed)
//   Point.ZERO.x            -> 0n                            (FAIL-OPEN)
//   Point.ZERO.hasEvenY()   -> true                          (FAIL-OPEN)
//
// So the identity point serialises fail-closed but reports an x-coordinate of zero
// and an even y with no throw. An adaptor layer that reads x(R+T) or the parity of
// R+T straight off the library would, for the degenerate R+T = O case, compute a
// well-formed-looking challenge over x = 0 and take the "even" branch -- a plausible
// wrong answer rather than an error. `xOnly` and `parityOf` below refuse the identity
// instead. This is written as code and asserted in a test, never left as a comment.

import { schnorr } from '@noble/curves/secp256k1.js'
import type { XOnly, SumParity } from './types'

export const Point = schnorr.Point
export type Pt = InstanceType<typeof Point>

/** Curve order n. */
export const N: bigint = Point.Fn.ORDER
/** Field prime p. */
export const P_FIELD: bigint = Point.Fp.ORDER
export const G: Pt = Point.BASE

export class CryptoInputError extends Error {}

/**
 * y-parity, computed from the affine y coordinate.
 *
 * @noble/curves does expose a `hasEvenY()` method at runtime, but it is absent from
 * the published `WeierstrassPoint<T>` type, so calling it would mean casting past the
 * type system on every parity decision this lab makes -- and parity is the thing most
 * likely to be wrong here. Computing it from `y` is total, typed, and obvious.
 * secp.test.ts cross-checks this against the library's own runtime method so the two
 * cannot drift apart silently.
 */
export function hasEvenY(pt: Pt): boolean {
  return pt.y % 2n === 0n
}

/** Reject the identity before anything reads a coordinate or a parity off it. */
export function assertNotIdentity(pt: Pt, label: string): Pt {
  if (pt.is0()) {
    throw new CryptoInputError(
      `${label} is the point at infinity. The library would report x = 0 and an even y ` +
        `for it without raising; this lab refuses it instead.`,
    )
  }
  return pt
}

/** Scalars must be in [1, n-1]. t = 0 and t = n are both rejected here. */
export function assertScalar(v: bigint, label: string): bigint {
  if (typeof v !== 'bigint') throw new CryptoInputError(`${label} is not a scalar`)
  if (v <= 0n || v >= N) {
    throw new CryptoInputError(`${label} must be in [1, n-1]; got ${v === 0n ? '0' : 'a value outside the group order'}`)
  }
  return v
}

/** x-only bytes of a point, refusing the identity. */
export function xOnly(pt: Pt, label = 'point'): XOnly {
  assertNotIdentity(pt, label)
  return numTo32(pt.x)
}

/** Parity of a point's y, refusing the identity. */
export function parityOf(pt: Pt, label = 'point'): SumParity {
  assertNotIdentity(pt, label)
  return hasEvenY(pt) ? 'even' : 'odd'
}

/** Scalar multiply with the range check in front of it. */
export function mulG(k: bigint, label = 'scalar'): Pt {
  return G.multiply(assertScalar(k, label))
}

export function mul(pt: Pt, k: bigint, label = 'scalar'): Pt {
  assertNotIdentity(pt, 'base point')
  return pt.multiply(assertScalar(k, label))
}

/** BIP-340 lift_x: the even-y point with this x. Throws on x >= p or non-curve x. */
export function liftX(x: XOnly | bigint): Pt {
  const v = typeof x === 'bigint' ? x : bytesToNum(x)
  if (v <= 0n || v >= P_FIELD) {
    throw new CryptoInputError(`x-coordinate must be in [1, p-1]`)
  }
  return schnorr.utils.lift_x(v)
}

export const mod = (a: bigint, m: bigint = N): bigint => ((a % m) + m) % m

/** Modular inverse via the library's scalar field, so we do not hand-roll it. */
export function invModN(a: bigint): bigint {
  const r = mod(a)
  if (r === 0n) throw new CryptoInputError('not invertible: value is 0 mod n')
  return Point.Fn.inv(r)
}

export function numTo32(v: bigint): Uint8Array {
  if (v < 0n || v >= 1n << 256n) throw new CryptoInputError('value does not fit in 32 bytes')
  const out = new Uint8Array(32)
  let x = v
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}

export function bytesToNum(b: Uint8Array): bigint {
  let v = 0n
  for (const byte of b) v = (v << 8n) | BigInt(byte)
  return v
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

export function fromHex(s: string): Uint8Array {
  const clean = s.trim().replace(/^0x/i, '')
  if (clean.length % 2 !== 0) throw new CryptoInputError('hex string has an odd length')
  if (clean.length && !/^[0-9a-fA-F]+$/.test(clean)) throw new CryptoInputError('not hexadecimal')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** BIP-340 tagged hash, straight from the library. */
export function taggedHash(tag: string, ...msgs: Uint8Array[]): Uint8Array {
  return schnorr.utils.taggedHash(tag, ...msgs)
}

/**
 * BIP-340 challenge: int(taggedHash("BIP0340/challenge", bytes(rx) || bytes(px) || m)) mod n.
 * rx here is the x of the nonce point the VERIFIER will see -- for an adaptor that is
 * x(R + T), not x(R).
 */
export function challenge(rx: XOnly, px: XOnly, msg: Uint8Array): bigint {
  return mod(bytesToNum(taggedHash('BIP0340/challenge', rx, px, msg)))
}

/** BIP-340 key normalisation: d = d' if y(d'G) is even else n - d'. */
export function normaliseSecret(secretKey: Uint8Array): { d: bigint; publicKey: XOnly; pointEven: Pt } {
  if (secretKey.length !== 32) throw new CryptoInputError('secret key must be 32 bytes')
  const dPrime = assertScalar(bytesToNum(secretKey), 'secret key')
  const full = G.multiply(dPrime)
  const d = hasEvenY(full) ? dPrime : N - dPrime
  const pointEven = G.multiply(d)
  return { d, publicKey: xOnly(pointEven, 'public key'), pointEven }
}
