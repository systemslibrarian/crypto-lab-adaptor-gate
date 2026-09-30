import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { recoverFromNonceReuse, wrongTDemo } from './attacks'
import { preSign, adaptorPoint } from './adaptor'
import { normaliseSecret, numTo32, hex, N, mod, G, liftX, invModN } from './secp'

const MSG = 'Alice pays Bob 0.10 units on ledger A'
const SK = numTo32(0x0a11ce0000000000000000000000000000000000000000000000000000000001n)
const T1 = 0x0b0b000000000000000000000000000000000000000000000000000000000001n

function reusePair(t1: bigint, t2: bigint, sk = SK) {
  const msg = new TextEncoder().encode(MSG)
  const a = adaptorPoint(t1)
  const b = adaptorPoint(t2)
  return {
    pre1: preSign(sk, msg, a.Tx, { mode: 'naive' }),
    pre2: preSign(sk, msg, b.Tx, { mode: 'naive' }),
    T1x: a.Tx,
    T2x: b.Tx,
  }
}

describe('Invariant 7 — nonce reuse recovers the key, and the forgery is real', () => {
  it('recovers d and the LIBRARY accepts a forged signature on a fresh message', () => {
    const { publicKey, d } = normaliseSecret(SK)
    const inputs = reusePair(T1, T1 + 1n)
    const r = recoverFromNonceReuse(inputs, publicKey, 'a message the signer never saw')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.d).toBe(d) // the actual key, by computation
    expect(r.dMatchesPublicKey).toBe(true)
    expect(r.forgery.libraryAccepts).toBe(true)
    // and independently: verify the forgery here too
    const msg = new TextEncoder().encode(r.forgery.message)
    expect(schnorr.verify(r.forgery.signature, msg, publicKey)).toBe(true)
  })

  it('exercises BOTH algebraic branches across many T pairs', () => {
    const { publicKey, d } = normaliseSecret(SK)
    const branches = new Set<string>()
    let recovered = 0
    for (let i = 1n; i <= 40n; i++) {
      const inputs = reusePair(T1, T1 + i)
      if (hex(inputs.T1x) === hex(inputs.T2x)) continue
      const r = recoverFromNonceReuse(inputs, publicKey, 'fresh')
      if (r.ok) {
        expect(r.d).toBe(d)
        branches.add(r.branch)
        recovered++
      }
    }
    expect(recovered).toBeGreaterThan(10)
    // If only one branch ever ran, the other is untested and could be silently wrong.
    expect(branches.has('same-parity')).toBe(true)
    expect(branches.has('opposite-parity')).toBe(true)
  })

  it('the opposite-parity branch needs the SUM; the difference form fails there', () => {
    // Proves the second branch is load-bearing rather than defensive decoration.
    const { publicKey, d } = normaliseSecret(SK)
    let checked = 0
    for (let i = 1n; i <= 60n && checked < 3; i++) {
      const inputs = reusePair(T1, T1 + i)
      if (inputs.pre1.parity === inputs.pre2.parity) continue
      const r = recoverFromNonceReuse(inputs, publicKey, 'fresh')
      expect(r.ok).toBe(true)
      if (!r.ok) continue
      expect(r.branch).toBe('opposite-parity')
      expect(r.d).toBe(d)
      // the naive difference formula gives the WRONG answer on this input
      const den = mod(inputs.pre1.e - inputs.pre2.e)
      const wrong = mod(mod(inputs.pre1.sHat - inputs.pre2.sHat) * invModN(den))
      expect(wrong).not.toBe(d)
      checked++
    }
    expect(checked).toBe(3)
  })

  it('reports "not recoverable" when both pre-signatures use the same T', () => {
    const { publicKey } = normaliseSecret(SK)
    const inputs = reusePair(T1, T1)
    const r = recoverFromNonceReuse(inputs, publicKey, 'fresh')
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.sharedNonce).toBe(true)
      expect(r.reason).toMatch(/same T|Not recoverable/)
    }
  })

  it('reports no shared nonce — and so no attack — in the bound default mode', () => {
    const { publicKey } = normaliseSecret(SK)
    const msg = new TextEncoder().encode(MSG)
    const a = adaptorPoint(T1)
    const b = adaptorPoint(T1 + 1n)
    const inputs = {
      pre1: preSign(SK, msg, a.Tx, { auxRand: numTo32(1n) }),
      pre2: preSign(SK, msg, b.Tx, { auxRand: numTo32(1n) }),
      T1x: a.Tx,
      T2x: b.Tx,
    }
    const r = recoverFromNonceReuse(inputs, publicKey, 'fresh')
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.sharedNonce).toBe(false)
      expect(r.reason).toMatch(/do not share a nonce/)
    }
  })

  it('the recovered key is the BIP-340 normalised d, and d*G is the even-y P', () => {
    const { publicKey } = normaliseSecret(SK)
    const r = recoverFromNonceReuse(reusePair(T1, T1 + 3n), publicKey, 'fresh')
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.d).toBeGreaterThan(0n)
      expect(r.d).toBeLessThan(N)
      expect(G.multiply(r.d).equals(liftX(publicKey))).toBe(true)
    }
  })
})

describe('Invariant 8 — wrong-T, as an attack', () => {
  it('the pre-signature is well-formed but points at the wrong secret', () => {
    const r = wrongTDemo(SK, MSG, T1, T1 + 4242n)
    expect(hex(r.TxReal)).not.toBe(hex(r.TxAttacker))
    expect(r.verifiesAgainstReal).toBe(false)
    expect(r.verifiesAgainstAttacker).toBe(true)
    expect(r.reasonAgainstReal.length).toBeGreaterThan(0)
  })
})
