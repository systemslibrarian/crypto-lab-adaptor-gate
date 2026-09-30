import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { runSwap, ALICE_SK, BOB_SK, MSG_A, MSG_B } from './swap'
import { createLedger, publishSpend, readPublishedSignature, refundAvailable } from './ledger'
import { preSign, adapt, adaptorPoint, preSignatureAsBytes } from './adaptor'
import { normaliseSecret, numTo32, hex } from './secp'

describe('Invariant 9 — swap atomicity at the model level', () => {
  it('the honest run pays both sides, in order', () => {
    const r = runSwap({ aliceCheats: false, bobSkipsPreVerify: false })
    expect(r.bobPreVerifyPassed).toBe(true)
    expect(r.aliceClaimedB).toBe(true)
    expect(r.bobClaimedA).toBe(true)
    expect(r.bobLostFunds).toBe(false)
    expect(r.ledgerA.spend).not.toBeNull()
    expect(r.ledgerB.spend).not.toBeNull()
    // the order is the lesson: B settles before A
    expect(r.ledgerB.spend!.atStep).toBeLessThan(r.ledgerA.spend!.atStep)
  })

  it("Bob's t is the value he extracted, and it is correct", () => {
    const r = runSwap({ aliceCheats: false, bobSkipsPreVerify: false })
    expect(r.bobExtractedT).not.toBeNull()
    expect(r.bobExtractedTCorrect).toBe(true)
  })

  it('before Alice publishes, there is nothing for Bob to extract from', () => {
    // Not "forbidden" -- not computable. Assert that directly on a fresh ledger.
    const r = runSwap({ aliceCheats: false, bobSkipsPreVerify: false })
    expect(r.earlyClaimPossible).toBe(false)
    expect(r.earlyClaimReason).toMatch(/not computable/)
    const bob = normaliseSecret(BOB_SK)
    const fresh = createLedger('B', bob.publicKey, '1500 units', MSG_B)
    expect(readPublishedSignature(fresh)).toBeNull()
  })

  it("Bob's claim on A really does depend on Alice's publish, not on a flag", () => {
    // Reconstruct the dependency by hand: with ledger B unspent, Bob has no bytes,
    // so there is no signature he can build for ledger A.
    const alice = normaliseSecret(ALICE_SK)
    const bob = normaliseSecret(BOB_SK)
    const ad = adaptorPoint(0x0decaf00000000000000000000000000000000000000000000000000000000abn)
    const msgA = new TextEncoder().encode(MSG_A)
    const preA = preSign(ALICE_SK, msgA, ad.Tx, { auxRand: numTo32(11n) })
    let ledgerA = createLedger('A', alice.publicKey, '0.10 units', MSG_A)
    const ledgerB = createLedger('B', bob.publicKey, '1500 units', MSG_B)
    expect(readPublishedSignature(ledgerB)).toBeNull()
    // the best Bob can do without t is publish the pre-signature itself
    const attempt = publishSpend(ledgerA, preSignatureAsBytes(preA), 'Bob', 2)
    expect(attempt.ok).toBe(false)
    if (!attempt.ok) expect(attempt.reason).toMatch(/not a valid BIP-340 signature/)
    expect(ledgerA.spend).toBeNull()
  })
})

describe('the wrong-T loss — scoped to the exact mechanism', () => {
  it('Bob loses funds when he skips pre-verification and Alice cheats', () => {
    const r = runSwap({ aliceCheats: true, bobSkipsPreVerify: true })
    expect(r.aliceClaimedB).toBe(true) // Alice took Bob's coins
    expect(r.bobClaimedA).toBe(false) // Bob got nothing
    expect(r.bobLostFunds).toBe(true)
  })

  it('and the cause is NOT a bad extraction — every check Bob ran passed', () => {
    // This is the claim the brief says is usually stated too broadly. Bob's extracted
    // t is RIGHT. The loss comes from the pre-signature committing to another point.
    const r = runSwap({ aliceCheats: true, bobSkipsPreVerify: true })
    expect(r.bobExtractedT).not.toBeNull()
    expect(r.bobExtractedTCorrect).toBe(true)
    expect(hex(r.TxAlicePreSignedAgainst)).not.toBe(hex(r.Tx))
  })

  it('running the check catches it and Bob loses nothing', () => {
    const r = runSwap({ aliceCheats: true, bobSkipsPreVerify: false })
    expect(r.bobPreVerifyRan).toBe(true)
    expect(r.bobPreVerifyPassed).toBe(false)
    expect(r.aliceClaimedB).toBe(false)
    expect(r.bobClaimedA).toBe(false)
    expect(r.bobLostFunds).toBe(false)
  })

  it('skipping the check is harmless when the counterparty is honest', () => {
    // Scoping again: the skip is not itself the loss. It is the loss only against a
    // counterparty who cheats.
    const r = runSwap({ aliceCheats: false, bobSkipsPreVerify: true })
    expect(r.aliceClaimedB).toBe(true)
    expect(r.bobClaimedA).toBe(true)
    expect(r.bobLostFunds).toBe(false)
  })
})

describe('the modeled ledger checks real signatures', () => {
  it('accepts only a valid BIP-340 signature under the locking key', () => {
    const bob = normaliseSecret(BOB_SK)
    const ledger = createLedger('B', bob.publicKey, '1500 units', MSG_B)
    const msg = new TextEncoder().encode(MSG_B)
    const good = schnorr.sign(msg, BOB_SK, new Uint8Array(32))
    expect(schnorr.verify(good, msg, bob.publicKey)).toBe(true)
    const ok = publishSpend(ledger, good, 'Bob', 1)
    expect(ok.ok).toBe(true)
    // wrong message
    const otherMsg = new TextEncoder().encode('Ledger B: 1500 units, Bob to Carol')
    const wrongMsgSig = schnorr.sign(otherMsg, BOB_SK, new Uint8Array(32))
    expect(publishSpend(ledger, wrongMsgSig, 'Bob', 1).ok).toBe(false)
    // wrong key
    const alice = normaliseSecret(ALICE_SK)
    const wrongKeySig = schnorr.sign(msg, ALICE_SK, new Uint8Array(32))
    expect(schnorr.verify(wrongKeySig, msg, alice.publicKey)).toBe(true)
    expect(publishSpend(ledger, wrongKeySig, 'Alice', 1).ok).toBe(false)
    // wrong length
    expect(publishSpend(ledger, new Uint8Array(32), 'Bob', 1).ok).toBe(false)
  })

  it('refuses a double spend', () => {
    const bob = normaliseSecret(BOB_SK)
    const ledger = createLedger('B', bob.publicKey, '1500 units', MSG_B)
    const msg = new TextEncoder().encode(MSG_B)
    const sig = schnorr.sign(msg, BOB_SK, new Uint8Array(32))
    const first = publishSpend(ledger, sig, 'Bob', 1)
    expect(first.ok).toBe(true)
    if (first.ok) {
      const second = publishSpend(first.state, sig, 'Bob', 2)
      expect(second.ok).toBe(false)
      if (!second.ok) expect(second.reason).toMatch(/already spent/)
    }
  })

  it('the modeled timelock opens a refund only while unspent', () => {
    const bob = normaliseSecret(BOB_SK)
    const ledger = createLedger('B', bob.publicKey, '1500 units', MSG_B, 6)
    expect(refundAvailable(ledger, 5)).toBe(false)
    expect(refundAvailable(ledger, 6)).toBe(true)
    const msg = new TextEncoder().encode(MSG_B)
    const spent = publishSpend(ledger, schnorr.sign(msg, BOB_SK, new Uint8Array(32)), 'Bob', 1)
    if (spent.ok) expect(refundAvailable(spent.state, 99)).toBe(false)
  })

  it('a pre-signature published as a spend is rejected by the ledger', () => {
    const bob = normaliseSecret(BOB_SK)
    const ledger = createLedger('B', bob.publicKey, '1500 units', MSG_B)
    const msgB = new TextEncoder().encode(MSG_B)
    const ad = adaptorPoint(0x0decaf00000000000000000000000000000000000000000000000000000000abn)
    const pre = preSign(BOB_SK, msgB, ad.Tx, { auxRand: numTo32(12n) })
    expect(publishSpend(ledger, preSignatureAsBytes(pre), 'Alice', 1).ok).toBe(false)
    // but the completed one is accepted
    const { signature } = adapt(pre, ad.t)
    expect(publishSpend(ledger, signature, 'Alice', 1).ok).toBe(true)
  })
})
