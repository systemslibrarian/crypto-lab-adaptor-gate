// The adaptor layer. This is the ONLY file in the lab that implements adaptor logic.
// It works on top of the chokepoint in ./secp.ts and never touches the curve library
// directly. The honest path and every attack in ./attacks.ts call these same four
// functions -- there is no parallel "attack mode" implementation.
//
// THE ONE RELATION EVERYTHING SERVES
//
//   s - s-hat  ==  +t  when R + T has even y
//   s - s-hat  ==  -t  when R + T has odd  y
//
// where T = t*G, R is the pre-signature's nonce point, and the completed signature
// carries x(R + T) as its nonce. The sign is not a detail: it is fixed by the parity
// of R + T, and getting it wrong is the classic adaptor bug, so the parity is carried
// explicitly on every PreSignature rather than recomputed at each use site.
//
// WHY THE COMPLETED SIGNATURE VERIFIES UNDER UNMODIFIED BIP-340
//
// BIP-340 verify(sig = (rx, s), px, m) accepts iff, with P = lift_x(px) and
// e = challenge(rx || px || m), the point s*G - e*P is not infinite, has even y, and
// has x equal to rx. Writing R_sum = R + T and P_even = d*G:
//
//   R_sum even:  need s*G = R_sum + e*P_even  => s = k' + t + e*d,  so s-hat = k' + e*d
//   R_sum odd:   lift_x(x(R_sum)) = -R_sum, so
//                need s*G = -R - T + e*P_even => s = -k' - t + e*d, so s-hat = -k' + e*d
//
// Both collapse to one line if we define k = k' when R_sum is even and k = n - k'
// when it is odd:
//
//   s-hat = k + e*d        and        s = s-hat (+/-) t
//
// which is what preSign, preVerify, adapt and extract below implement.

import {
  N,
  G,
  mod,
  mulG,
  liftX,
  xOnly,
  parityOf,
  challenge,
  normaliseSecret,
  numTo32,
  bytesToNum,
  taggedHash,
  assertScalar,
  assertNotIdentity,
  hasEvenY,
  CryptoInputError,
  type Pt,
} from './secp'
import type {
  XOnly,
  PreSignature,
  PreVerifyResult,
  ExtractResult,
  SumParity,
  AdaptorSecret,
} from './types'

export { CryptoInputError }

/**
 * Build T from an adaptor scalar, normalising t exactly the way BIP-340 normalises a
 * secret key.
 *
 * T travels as 32 x-only bytes, so the point it denotes is always the even-y lift of
 * that x. If t*G happens to have odd y then the point behind those bytes is (n-t)*G,
 * not t*G, and the adaptor relation would be off by a sign that nothing later could
 * detect. So we negate the scalar instead, as BIP-340 does for d:
 *
 *   t_norm = t if y(t*G) is even, else n - t
 *
 * t_norm is then the secret that completing the signature actually reveals, and
 * t_norm*G == lift_x(T) holds by construction. `negated` is returned so the UI can
 * say so rather than silently handing back a different number than the user typed.
 */
export function adaptorPoint(t: bigint): AdaptorSecret & { negated: boolean } {
  assertScalar(t, 'adaptor secret t')
  const full = mulG(t, 'adaptor secret t')
  const negated = !hasEvenY(full)
  const tNorm = negated ? N - mod(t) : mod(t)
  const T = mulG(tNorm, 'adaptor secret t')
  return { t: tNorm, Tx: xOnly(T, 'adaptor point T'), negated }
}

export type NonceMode = 'bound' | 'naive'

/**
 * Nonce derivation. Two modes, and the difference between them is the whole of
 * exhibit 7.
 *
 * 'bound' (the default) is BIP-340's own nonce function with the adaptor point mixed
 * in. BIP-340 hashes  t_aux || bytes(x(P)) || m ; this hashes
 *
 *     t_aux || bytes(x(P)) || bytes(x(T)) || m
 *
 * with t_aux = d XOR taggedHash("BIP0340/aux", aux_rand), exactly as BIP-340 defines
 * it. The 32 bytes of x(T) sit between the public key and the message. BIP-340
 * specifies no adaptor nonce function, so this placement is this lab's construction
 * and is labelled as such in the UI -- it is not a standard.
 *
 * 'naive' derives the nonce from the message alone:  taggedHash("BIP0340/nonce", m).
 * Two pre-signatures on one message then share R no matter which T they are built
 * against, which is what makes the key recoverable in attacks.ts.
 */
export function deriveNonce(
  mode: NonceMode,
  d: bigint,
  px: XOnly,
  Tx: XOnly,
  msg: Uint8Array,
  auxRand: Uint8Array,
): bigint {
  if (mode === 'naive') {
    const k = mod(bytesToNum(taggedHash('BIP0340/nonce', msg)))
    if (k === 0n) throw new CryptoInputError('naive nonce derived to 0')
    return k
  }
  const aux = taggedHash('BIP0340/aux', auxRand)
  const dBytes = numTo32(d)
  const tAux = new Uint8Array(32)
  for (let i = 0; i < 32; i++) tAux[i] = dBytes[i] ^ aux[i]
  const k = mod(bytesToNum(taggedHash('BIP0340/nonce', tAux, px, Tx, msg)))
  if (k === 0n) throw new CryptoInputError('nonce derived to 0')
  return k
}

/**
 * Pre-sign message `msg` against adaptor point `T`.
 *
 * Returns R (not R + T) as rx, because R is what the counterparty must keep in order
 * to extract later, and x(R + T) as sumX, because that is the nonce the finished
 * signature will carry.
 */
export function preSign(
  secretKey: Uint8Array,
  msg: Uint8Array,
  Tx: XOnly,
  opts: { mode?: NonceMode; auxRand?: Uint8Array } = {},
): PreSignature {
  const mode = opts.mode ?? 'bound'
  const auxRand = opts.auxRand ?? new Uint8Array(32)
  const { d, publicKey } = normaliseSecret(secretKey)
  const T = liftX(Tx)
  assertNotIdentity(T, 'adaptor point T')

  const kPrime = deriveNonce(mode, d, publicKey, Tx, msg, auxRand)
  // R travels as 32 x-only bytes, so the verifier reconstructs it as lift_x(x(R)) --
  // the EVEN-y point. Normalise k' to match, or R + T is built from one point and
  // pre-verified against its negation. Same move as BIP-340 makes for d, and for T
  // in adaptorPoint above; skipping it here is the classic adaptor sign bug.
  const R0 = mulG(kPrime, 'nonce k')
  const kR = hasEvenY(R0) ? kPrime : N - kPrime
  const R = mulG(kR, 'nonce k')
  const Rsum = R.add(T)
  // R + T = O is reachable when T = -R. The chokepoint refuses it rather than
  // letting the library hand back x = 0 with an even-y verdict.
  assertNotIdentity(Rsum, 'R + T')

  const parity = parityOf(Rsum, 'R + T')
  const k = parity === 'even' ? kR : N - kR
  const sumX = xOnly(Rsum, 'R + T')
  const e = challenge(sumX, publicKey, msg)
  const sHat = mod(k + e * d)

  return { rx: xOnly(R, 'nonce point R'), sHat, sumX, parity, e }
}

/**
 * Pre-verify: does this pre-signature really commit to T under this key and message?
 *
 *   s-hat * G  ==  R_adj + e * P_even ,   R_adj = R if R + T is even, else -R
 *
 * Computed both sides and compared as points. A pre-signature built against some
 * other T* fails here -- that is the check the "skip pre-verify" toggle in exhibit 5
 * turns off, and the loss it causes is the reason the check exists.
 */
export function preVerify(
  pre: PreSignature,
  px: XOnly,
  msg: Uint8Array,
  Tx: XOnly,
): PreVerifyResult {
  try {
    const P = liftX(px)
    const T = liftX(Tx)
    const R = liftX(pre.rx)
    assertNotIdentity(T, 'adaptor point T')

    // Recompute R + T from the claimed R and the T we are checking against, rather
    // than trusting the parity and sumX the pre-signature carries.
    const Rsum = R.add(T)
    if (Rsum.is0()) return { ok: false, reason: 'R + T is the point at infinity' }
    const parity = parityOf(Rsum, 'R + T')
    const sumX = xOnly(Rsum, 'R + T')

    if (parity !== pre.parity) {
      return { ok: false, reason: `parity of R + T is ${parity}, pre-signature claims ${pre.parity}` }
    }
    if (!eqBytes(sumX, pre.sumX)) {
      return { ok: false, reason: 'x(R + T) does not match the value the pre-signature carries' }
    }

    const e = challenge(sumX, px, msg)
    if (e !== pre.e) {
      return { ok: false, reason: 'challenge e does not match the value the pre-signature carries' }
    }

    const lhs = mulG(pre.sHat, 's-hat')
    const Radj = parity === 'even' ? R : R.negate()
    const rhs = Radj.add(P.multiply(e))
    if (!lhs.equals(rhs)) {
      return { ok: false, reason: 's-hat * G != R_adj + e * P' }
    }
    return { ok: true, e }
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'pre-verification failed' }
  }
}

/**
 * Complete the pre-signature with the adaptor secret.
 *   s = s-hat + t  (R + T even)   |   s = s-hat - t  (R + T odd)
 * The result is a 64-byte BIP-340 signature x(R+T) || s, which the library's own
 * unmodified verify accepts.
 */
export function adapt(pre: PreSignature, t: bigint): { s: bigint; signature: Uint8Array } {
  assertScalar(t, 'adaptor secret t')
  const s = pre.parity === 'even' ? mod(pre.sHat + t) : mod(pre.sHat - t)
  return { s, signature: concat64(pre.sumX, s) }
}

/**
 * Recover t from a pre-signature and the completed signature.
 *   t = s - s-hat  (R + T even)   |   t = s-hat - s  (R + T odd)
 *
 * Fails rather than returning a wrong t when the two do not belong together: the
 * signature's nonce must be the pre-signature's x(R + T), and the recovered t must
 * satisfy t*G == T for the T the caller expected.
 */
export function extract(pre: PreSignature, signature: Uint8Array, expectedTx?: XOnly): ExtractResult {
  try {
    if (signature.length !== 64) return { ok: false, reason: 'signature must be 64 bytes' }
    const sigRx = signature.slice(0, 32)
    const s = bytesToNum(signature.slice(32))
    if (!eqBytes(sigRx, pre.sumX)) {
      return {
        ok: false,
        reason: "the signature's nonce is not this pre-signature's x(R + T), so the two do not pair",
      }
    }
    if (s <= 0n || s >= N) return { ok: false, reason: 's is outside [1, n-1]' }

    const t = pre.parity === 'even' ? mod(s - pre.sHat) : mod(pre.sHat - s)
    if (t === 0n) {
      return { ok: false, reason: 's - s-hat is 0 mod n: no adaptor secret was added' }
    }
    const T = mulG(t, 'recovered t')
    const Tx = xOnly(T, 'recovered T')
    if (expectedTx && !eqBytes(Tx, expectedTx)) {
      return { ok: false, reason: 'recovered t*G does not equal the expected T' }
    }
    return { ok: true, t, Tx }
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'extraction failed' }
  }
}

/**
 * The 64 bytes a pre-signature would be if someone tried to pass it off as a
 * signature: x(R + T) || s-hat. Invariant 1 says BIP-340 verify must reject this.
 * Built here so the page can hand the real verifier a real byte string rather than
 * asserting the rejection in prose.
 */
export function preSignatureAsBytes(pre: PreSignature): Uint8Array {
  return concat64(pre.sumX, pre.sHat)
}

export function concat64(rx: XOnly, s: bigint): Uint8Array {
  const out = new Uint8Array(64)
  out.set(rx, 0)
  out.set(numTo32(mod(s)), 32)
  return out
}

export function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Exposed for the UI's parity strip: which branch a given R, T pair lands on. */
export function sumParityOf(rx: XOnly, Tx: XOnly): { parity: SumParity; sumX: XOnly } {
  const Rsum = liftX(rx).add(liftX(Tx))
  assertNotIdentity(Rsum, 'R + T')
  return { parity: parityOf(Rsum, 'R + T'), sumX: xOnly(Rsum, 'R + T') }
}

export type { Pt }
export { G, N }
