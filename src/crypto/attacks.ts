// Attacks. Every one of these calls the SAME functions in ./adaptor.ts that the
// honest path calls -- there is no second, deliberately-weakened implementation of
// the adaptor maths anywhere in this lab. The only thing an attack changes is the
// INPUTS: which nonce mode the signer used, or which T a pre-signature was built
// against. That is the whole point: the failure has to come from the real
// construction being misused, not from a mock that was written to fail.

import { schnorr } from '@noble/curves/secp256k1.js'
import { preSign, preVerify, adaptorPoint, eqBytes } from './adaptor'
import {
  mod,
  mulG,
  liftX,
  invModN,
  numTo32,
  normaliseSecret,
  hex,
  type Pt,
} from './secp'
import type { PreSignature, XOnly } from './types'

// ---------------------------------------------------------------------------
// 1. Nonce reuse -> secret key recovery
// ---------------------------------------------------------------------------

export interface ReuseInputs {
  pre1: PreSignature
  pre2: PreSignature
  T1x: XOnly
  T2x: XOnly
}

export type ReuseResult =
  | {
      ok: true
      /** Which algebraic branch the recovery used. */
      branch: 'same-parity' | 'opposite-parity'
      /** The equation, rendered for the page rather than described in prose. */
      equation: string
      d: bigint
      /** Proof the recovered scalar is the real key: d*G compared to P. */
      dMatchesPublicKey: boolean
      /** A signature on a FRESH message, made with the recovered key. */
      forgery: { message: string; signature: Uint8Array; libraryAccepts: boolean }
    }
  | { ok: false; reason: string; sharedNonce: boolean }

/**
 * Recover the signing key from two pre-signatures that reused a nonce.
 *
 * The parity rule makes this two equations, not one, and the second is easy to miss.
 * With kR the normalised nonce scalar and k_i the value actually used for
 * pre-signature i:
 *
 *   both R+T_i even, or both odd   =>  k1 == k2, so
 *                                      s1 - s2 = (e1 - e2) d   =>  d = (s1-s2)/(e1-e2)
 *
 *   one even and one odd           =>  k1 = kR, k2 = n - kR, so the nonce CANCELS
 *                                      in the SUM instead:
 *                                      s1 + s2 = (e1 + e2) d   =>  d = (s1+s2)/(e1+e2)
 *
 * A recovery that only implements the difference branch silently fails on half its
 * inputs, so both are implemented and the page names which one it used.
 */
export function recoverFromNonceReuse(
  inputs: ReuseInputs,
  publicKey: XOnly,
  freshMessage: string,
): ReuseResult {
  const { pre1, pre2, T1x, T2x } = inputs
  const sharedNonce = eqBytes(pre1.rx, pre2.rx)

  if (!sharedNonce) {
    return {
      ok: false,
      sharedNonce: false,
      reason:
        'The two pre-signatures do not share a nonce: R differs, so there is no ' +
        'common unknown to cancel and no equation to solve. This is what binding T ' +
        'into the nonce derivation buys.',
    }
  }
  if (eqBytes(T1x, T2x)) {
    return {
      ok: false,
      sharedNonce: true,
      reason:
        'Both pre-signatures are against the same T, so e1 == e2 and both branches ' +
        'reduce to 0 = 0. Not recoverable from these two.',
    }
  }

  const sameParity = pre1.parity === pre2.parity
  let d: bigint
  let equation: string
  try {
    if (sameParity) {
      const den = mod(pre1.e - pre2.e)
      if (den === 0n) {
        return { ok: false, sharedNonce: true, reason: 'e1 - e2 is 0 mod n: not recoverable from these two.' }
      }
      d = mod(mod(pre1.sHat - pre2.sHat) * invModN(den))
      equation = 'd = (ŝ₁ − ŝ₂) / (e₁ − e₂) mod n'
    } else {
      const den = mod(pre1.e + pre2.e)
      if (den === 0n) {
        return { ok: false, sharedNonce: true, reason: 'e1 + e2 is 0 mod n: not recoverable from these two.' }
      }
      d = mod(mod(pre1.sHat + pre2.sHat) * invModN(den))
      equation = 'd = (ŝ₁ + ŝ₂) / (e₁ + e₂) mod n'
    }
  } catch (err) {
    return { ok: false, sharedNonce: true, reason: err instanceof Error ? err.message : 'recovery failed' }
  }

  if (d === 0n) {
    return { ok: false, sharedNonce: true, reason: 'recovery produced 0, which is not a valid key' }
  }

  // Is the recovered scalar really the key? Compare d*G against P by computation.
  let dMatchesPublicKey = false
  try {
    dMatchesPublicKey = mulG(d, 'recovered d').equals(liftX(publicKey))
  } catch {
    dMatchesPublicKey = false
  }

  // The proof that matters: sign a message the signer never touched, and hand it to
  // the library's own unmodified verifier under the original public key.
  const msgBytes = new TextEncoder().encode(freshMessage)
  let signature = new Uint8Array(64)
  let libraryAccepts = false
  try {
    signature = schnorr.sign(msgBytes, numTo32(d), numTo32(0x5eedn))
    libraryAccepts = schnorr.verify(signature, msgBytes, publicKey)
  } catch {
    libraryAccepts = false
  }

  return {
    ok: true,
    branch: sameParity ? 'same-parity' : 'opposite-parity',
    equation,
    d,
    dMatchesPublicKey,
    forgery: { message: freshMessage, signature, libraryAccepts },
  }
}

// ---------------------------------------------------------------------------
// 2. Wrong-T: a pre-signature that commits to a different secret than you think
// ---------------------------------------------------------------------------

export interface WrongTResult {
  /** Pre-signature built against the attacker's T*, offered as if it were against T. */
  pre: PreSignature
  TxReal: XOnly
  TxAttacker: XOnly
  /** preVerify against the T the victim cares about -- this is the check that saves them. */
  verifiesAgainstReal: boolean
  reasonAgainstReal: string
  /** preVerify against T*, to show the pre-signature is perfectly well-formed in itself. */
  verifiesAgainstAttacker: boolean
}

/**
 * Bob pre-signs against T* instead of the T Alice's payment is locked to.
 *
 * The pre-signature is not malformed -- it pre-verifies fine against T*. It is
 * simply a commitment to the wrong secret, and the ONLY thing standing between
 * Alice and a loss is running preVerify against the T she actually cares about.
 */
export function wrongTDemo(
  secretKey: Uint8Array,
  message: string,
  tReal: bigint,
  tAttacker: bigint,
): WrongTResult {
  const msg = new TextEncoder().encode(message)
  const { publicKey } = normaliseSecret(secretKey)
  const real = adaptorPoint(tReal)
  const fake = adaptorPoint(tAttacker)

  const pre = preSign(secretKey, msg, fake.Tx, { auxRand: numTo32(7n) })
  const againstReal = preVerify(pre, publicKey, msg, real.Tx)
  const againstFake = preVerify(pre, publicKey, msg, fake.Tx)

  return {
    pre,
    TxReal: real.Tx,
    TxAttacker: fake.Tx,
    verifiesAgainstReal: againstReal.ok,
    reasonAgainstReal: againstReal.ok ? '' : againstReal.reason,
    verifiesAgainstAttacker: againstFake.ok,
  }
}

export { hex }
export type { Pt }
