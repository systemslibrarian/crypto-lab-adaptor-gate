// PTLC routing -- MODELED. Three hops, no channel state, no fees, no network.
//
// TWO THINGS THIS EXHIBIT HAS TO GET RIGHT, and the second one is easy to fake.
//
// 1. DECORRELATION. Every hop carries a DIFFERENT adaptor point, where an HTLC
//    would carry the same payment hash on all of them. Both strips are computed
//    from one run, so the comparison is a measurement rather than an illustration.
//
// 2. CAUSALITY. Settlement runs backward, and each hop must be completed with the
//    secret its payee DERIVED from the hop it just paid -- extracted value plus its
//    own blinding scalar -- not with a value precomputed by the route builder.
//
//    An earlier version of this file failed (2) while appearing to pass it. It
//    computed every hop secret up front and then settled each hop with its own
//    precomputed `secret`, recording the extracted value alongside for display. The
//    numbers matched, the screen said "extraction propagates backward", and a test
//    separately proved the derivation *could* work -- but the state transition took
//    a shortcut, so corrupting a downstream signature would not have stopped an
//    upstream hop. Right answer, wrong causal chain.
//
//    The fix is structural rather than a comment: `settleNext` below has access to
//    exactly one secret, `carried`, and that is the only value it can complete a hop
//    with. The precomputed secrets survive only as an EXPECTED value to compare
//    against, never as an input to settlement. Break the chain anywhere and every
//    hop upstream of the break stops -- which is what `corrupt` exists to
//    demonstrate, and what ptlc.test.ts asserts.
//
// A note on the brief: its scope and this exhibit's heading both say THREE hops,
// while its example path names three parties (Alice -> Bob -> Carol), which is two
// hops. Three hops is built here, so a fourth node is needed and the path is
// Alice -> Bob -> Carol -> Dave.
//
// THE x-ONLY NORMALISATION STEP IS REAL, NOT BOOKKEEPING. T travels as 32 x-only
// bytes, so the scalar behind it is always the even-y one. A node that adds its
// blinding must therefore re-normalise afterwards -- and it CAN, locally, because
// normalisation is a deterministic public function of the scalar. That is why the
// derivation below reads `adaptorPoint(extracted + blinding)` rather than a plain
// addition.

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { preSign, preVerify, adapt, extract, adaptorPoint } from './adaptor'
import { mod, numTo32, hex, normaliseSecret, N } from './secp'
import type { XOnly, PreSignature } from './types'

export interface HopSpec {
  index: number
  payer: string
  payee: string
  /** The payer's signing key for this hop's modeled channel output. */
  payerSecretKey: Uint8Array
  /**
   * Blinding scalar handed to the payee of THIS hop. After settling hop i, the
   * payee adds this to what it extracted to get the secret for hop i-1.
   */
  blinding: bigint
}

export type HopStatus = 'waiting' | 'settled' | 'blocked'

export interface HopResult {
  index: number
  payer: string
  payee: string
  /** PTLC: this hop's adaptor point, x-only. Differs per hop. */
  Tx: XOnly
  /**
   * The secret the route builder intended for this hop. Used ONLY as an expected
   * value to compare the derived one against -- never as an input to settlement.
   */
  expectedSecret: bigint
  /** HTLC contrast: the payment hash, IDENTICAL on every hop. */
  htlcHash: XOnly
  publicKey: XOnly
  message: Uint8Array
  /**
   * The blinding scalar the PAYEE of this hop holds. After this hop settles, that
   * payee adds it to what it extracted to derive the secret for the hop upstream.
   * It lives on the state because settlement must be able to reach it -- and must
   * NOT be able to reach the route builder's precomputed secrets.
   */
  blinding: bigint
  pre: PreSignature
  preVerifies: boolean
  status: HopStatus
  /** The secret this hop was actually completed with, if it settled. */
  usedSecret: bigint | null
  /** What the payer extracted from the published signature. */
  extractedSecret: bigint | null
  extractionMatches: boolean
  signature: Uint8Array | null
  /** Set when the hop could not settle, naming why. */
  blockedReason: string
}

/** Ways to break the chain, for the exhibit's break-it controls. */
export interface PtlcFaults {
  /** Corrupt the signature published at this hop index (1-based), so extraction fails. */
  corruptSignatureAtHop?: number
  /** Give the payee of this hop (1-based) the wrong blinding scalar. */
  wrongBlindingAtHop?: number
}

export interface PtlcState {
  hops: HopResult[]
  z: bigint
  paymentPointX: XOnly
  htlcHash: XOnly
  message: string
  faults: PtlcFaults
  /** Index of the hop that settles next. Starts at the LAST hop. -1 when finished. */
  cursor: number
  /**
   * The only secret settlement may use. Seeded with z (which only the recipient
   * knows) and thereafter replaced by each hop's derived value. null means the
   * chain is broken and nothing upstream can settle.
   */
  carried: bigint | null
  /** Human-readable transitions, in the order they happened. */
  log: string[]
  broken: boolean
  brokenReason: string
  distinctPtlcPoints: number
  distinctHtlcHashes: number
}

/**
 * Build the route. Alice, who constructs the path, is the one party who legitimately
 * knows z and every blinding, so she can derive every hop point up front:
 *
 *   t_3 = z,   t_2 = norm(t_3 + b_3),   t_1 = norm(t_2 + b_2)
 *
 * Nothing is settled here. Settlement is `settleNext`.
 */
export function startPtlc(
  hops: HopSpec[],
  z: bigint,
  message: string,
  faults: PtlcFaults = {},
): PtlcState {
  if (hops.length < 2) throw new Error('a routed payment needs at least two hops')
  const htlcHash = sha256(numTo32(mod(z)))
  const last = hops.length - 1

  const secrets: bigint[] = new Array(hops.length)
  secrets[last] = adaptorPoint(z).t
  for (let i = last - 1; i >= 0; i--) {
    secrets[i] = adaptorPoint(mod(secrets[i + 1] + hops[i + 1].blinding)).t
  }

  const results: HopResult[] = hops.map((h, i) => {
    const ad = adaptorPoint(secrets[i])
    const { publicKey } = normaliseSecret(h.payerSecretKey)
    const msg = hopMessage(message, h)
    const pre = preSign(h.payerSecretKey, msg, ad.Tx, { auxRand: numTo32(BigInt(i + 1)) })
    return {
      index: h.index,
      payer: h.payer,
      payee: h.payee,
      Tx: ad.Tx,
      expectedSecret: ad.t,
      htlcHash,
      publicKey,
      message: msg,
      blinding: h.blinding,
      pre,
      preVerifies: preVerify(pre, publicKey, msg, ad.Tx).ok,
      status: 'waiting',
      usedSecret: null,
      extractedSecret: null,
      extractionMatches: false,
      signature: null,
      blockedReason: '',
    }
  })

  return {
    hops: results,
    z: mod(z),
    paymentPointX: adaptorPoint(z).Tx,
    htlcHash,
    message,
    faults,
    cursor: last,
    // ONLY the recipient starts with z.
    carried: adaptorPoint(z).t,
    log: [],
    broken: false,
    brokenReason: '',
    distinctPtlcPoints: new Set(results.map((r) => hex(r.Tx))).size,
    distinctHtlcHashes: new Set(results.map((r) => hex(r.htlcHash))).size,
  }
}

export function hopMessage(message: string, h: { index: number; payer: string; payee: string }): Uint8Array {
  return new TextEncoder().encode(`${message} [hop ${h.index}: ${h.payer} -> ${h.payee}]`)
}

export const ptlcFinished = (s: PtlcState): boolean => s.cursor < 0

/**
 * Settle ONE hop, the one at the cursor, and move the cursor upstream.
 *
 * The hop is completed with `state.carried` and with nothing else. That is the whole
 * causal argument: this function cannot reach the route builder's precomputed
 * secrets, so a hop settles if and only if the value that arrived from downstream is
 * the right one.
 */
export function settleNext(state: PtlcState): PtlcState {
  if (ptlcFinished(state)) return state
  const i = state.cursor
  const hops = state.hops.map((h) => ({ ...h }))
  const r = hops[i]
  const log = [...state.log]

  // The chain is already broken: this hop cannot settle, and neither can any before it.
  if (state.carried === null) {
    r.status = 'blocked'
    r.blockedReason =
      'no usable secret arrived from downstream, so there is nothing to complete this ' +
      'pre-signature with'
    log.push(`hop ${r.index} BLOCKED — ${r.blockedReason}`)
    return { ...state, hops, log, cursor: i - 1 }
  }

  // Complete with the carried value, and ONLY the carried value.
  const used = state.carried
  const { signature } = adapt(r.pre, used)
  r.usedSecret = used

  // Fault injection: a corrupted publication at this hop.
  let published = signature
  if (state.faults.corruptSignatureAtHop === r.index) {
    published = new Uint8Array(signature)
    published[63] ^= 0x01
  }
  r.signature = published

  // Does the real verifier accept what was published? This is the modeled channel's
  // only spend rule, and it is a real BIP-340 check.
  const accepted = schnorr.verify(published, r.message, r.publicKey)
  if (!accepted) {
    r.status = 'blocked'
    r.blockedReason =
      state.faults.corruptSignatureAtHop === r.index
        ? 'the signature published at this hop is corrupt, so the channel rejects it'
        : 'the completed signature is not valid under this hop payer key'
    log.push(`hop ${r.index} BLOCKED — ${r.blockedReason}`)
    return {
      ...state,
      hops,
      log,
      cursor: i - 1,
      carried: null,
      broken: true,
      brokenReason: r.blockedReason,
    }
  }

  r.status = 'settled'
  log.push(`hop ${r.index} settled (${r.payer} -> ${r.payee})`)

  // The PAYER of this hop now extracts from what was published. Nothing is handed
  // to it.
  const ex = extract(r.pre, published, r.Tx)
  r.extractedSecret = ex.ok ? ex.t : null
  r.extractionMatches = ex.ok && ex.t === r.expectedSecret

  if (!ex.ok) {
    log.push(`hop ${r.index} extraction FAILED — ${ex.reason}`)
    return { ...state, hops, log, cursor: i - 1, carried: null, broken: true, brokenReason: ex.reason }
  }

  // Derive the secret for the hop UPSTREAM of this one: what was just extracted,
  // plus the blinding this payee holds, re-normalised for the x-only convention.
  let carried: bigint | null = null
  if (i > 0) {
    const blinding =
      state.faults.wrongBlindingAtHop === r.index ? mod(r.blinding + 1n) : r.blinding
    carried = adaptorPoint(mod(ex.t + blinding)).t
    log.push(
      `hop ${r.index} payer derived the hop ${r.index - 1} secret from what it extracted`,
    )
  }

  return { ...state, hops, log, cursor: i - 1, carried }
}

export function settleAll(state: PtlcState): PtlcState {
  let s = state
  let guard = 0
  while (!ptlcFinished(s) && guard++ < 64) s = settleNext(s)
  return s
}

/** Default three-hop path, deterministic so the page and the tests agree. */
export function defaultPtlcPath(): { hops: HopSpec[]; z: bigint; message: string } {
  const key = (n: bigint) => numTo32(0x0c0ffee000000000000000000000000000000000000000000000000000000000n + n)
  return {
    z: 0x0d00d1e000000000000000000000000000000000000000000000000000000042n % N,
    message: 'Route 0.05 units to Dave',
    hops: [
      { index: 1, payer: 'Alice', payee: 'Bob', payerSecretKey: key(1n), blinding: 0n },
      { index: 2, payer: 'Bob', payee: 'Carol', payerSecretKey: key(2n), blinding: 0x1111111111111111111111111111111111111111111111111111111111111111n },
      { index: 3, payer: 'Carol', payee: 'Dave', payerSecretKey: key(3n), blinding: 0x2222222222222222222222222222222222222222222222222222222222222222n },
    ],
  }
}
