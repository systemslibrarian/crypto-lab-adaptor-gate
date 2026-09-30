// MODELED ledgers. Not a blockchain, not Bitcoin, not Lightning.
//
// Each ledger is a deterministic state machine holding one output whose spend
// condition is exactly: "a valid BIP-340 signature under key P over this spend
// message." The signature check is REAL -- it is the library's own unmodified
// schnorr.verify. Everything around it is a model.
//
// What a real deployment would do instead: lock the coins into a 2-of-2 joint key
// with a timelocked refund path, so neither party can move them alone and a stall
// resolves after the timeout. That is MuSig territory; modelling the lock keeps the
// adaptor arithmetic in view, which is what this lab is about.
//
// This file deliberately does NOT import ./adaptor.ts. A ledger has no idea what an
// adaptor signature is; it checks a signature. That separation is what makes the
// swap exhibit's atomicity claim mean anything -- the value Bob spends with is one he
// read out of ledger B's published state, not one handed to him from Alice's panel.

import { schnorr } from '@noble/curves/secp256k1.js'
import type { XOnly } from './types'

export type LedgerId = 'A' | 'B'

export interface Output {
  /** Whose signature unlocks it: an x-only BIP-340 key. */
  lockedTo: XOnly
  amount: string
  /** The message a spending signature must be over. */
  spendMessage: string
}

export interface SpendRecord {
  /** The 64-byte BIP-340 signature that unlocked the output. */
  signature: Uint8Array
  spentBy: string
  /** Step number at which it landed, for the modeled timelock. */
  atStep: number
}

export interface LedgerState {
  id: LedgerId
  output: Output
  /** Null until a valid signature is published. This is the ledger's whole memory. */
  spend: SpendRecord | null
  /** Modeled timelock: a step counter, not a consensus rule. */
  refundAvailableAtStep: number
}

export type PublishResult =
  | { ok: true; state: LedgerState }
  | { ok: false; reason: string }

export function createLedger(
  id: LedgerId,
  lockedTo: XOnly,
  amount: string,
  spendMessage: string,
  refundAvailableAtStep = 6,
): LedgerState {
  return { id, output: { lockedTo, amount, spendMessage }, spend: null, refundAvailableAtStep }
}

/**
 * Publish a spend. The ONLY acceptance rule is the library's BIP-340 verify over the
 * output's own spend message and locking key. A pre-signature published here is
 * rejected for the same reason any other 64 bytes would be: it does not verify.
 */
export function publishSpend(
  state: LedgerState,
  signature: Uint8Array,
  spentBy: string,
  atStep: number,
): PublishResult {
  if (state.spend) {
    return { ok: false, reason: `ledger ${state.id} is already spent` }
  }
  if (signature.length !== 64) {
    return { ok: false, reason: 'a spend must carry a 64-byte BIP-340 signature' }
  }
  const msg = new TextEncoder().encode(state.output.spendMessage)
  let accepted = false
  try {
    accepted = schnorr.verify(signature, msg, state.output.lockedTo)
  } catch {
    accepted = false
  }
  if (!accepted) {
    return {
      ok: false,
      reason: `ledger ${state.id} rejected it: not a valid BIP-340 signature under the locking key`,
    }
  }
  return { ok: true, state: { ...state, spend: { signature, spentBy, atStep } } }
}

/**
 * What an observer of this ledger can read. This is the ONLY route by which the swap
 * exhibit lets Bob learn the completed signature -- he reads the chain, he is not
 * told.
 */
export function readPublishedSignature(state: LedgerState): Uint8Array | null {
  return state.spend ? state.spend.signature : null
}

export function refundAvailable(state: LedgerState, currentStep: number): boolean {
  return !state.spend && currentStep >= state.refundAvailableAtStep
}
