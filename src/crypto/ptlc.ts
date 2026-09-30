// PTLC routing -- MODELED. Three hops, no channel state, no fees, no network.
//
// The point of this exhibit is one comparison, computed from a single run rather
// than drawn:
//
//   HTLC:  every hop carries H(z), THE SAME 32 BYTES. Hop 1 and hop 3 are linkable
//          by anyone who sees both, because the identifier is literally equal.
//   PTLC:  every hop carries a DIFFERENT point T_i. Learning one tells an observer
//          nothing about the others.
//
// The chain is built with real adaptor pre-signatures from ./adaptor.ts, and the
// secrets really do propagate backward: each node extracts the secret for the hop it
// paid, adds its own blinding scalar, and that is the secret it needs to claim its
// own incoming hop.
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
// chain below reads `adaptorPoint(previous + blinding)` at every step rather than
// plain addition.

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
  /** Blinding scalar the payee of this hop was handed, to derive the secret. */
  blinding: bigint
}

export interface HopResult {
  index: number
  payer: string
  payee: string
  /** PTLC: this hop's adaptor point, x-only. Differs per hop. */
  Tx: XOnly
  /** The normalised secret that unlocks this hop. */
  secret: bigint
  /** HTLC contrast: the payment hash, IDENTICAL on every hop. */
  htlcHash: XOnly
  publicKey: XOnly
  pre: PreSignature
  preVerifies: boolean
  /** Filled in during settlement, which runs backward from the last hop. */
  settled: boolean
  /** The secret the payer EXTRACTED from the completed signature. */
  extractedSecret: bigint | null
  extractionMatches: boolean
  signature: Uint8Array | null
}

export interface PtlcRun {
  hops: HopResult[]
  /** Dave's invoice secret. */
  z: bigint
  paymentPointX: XOnly
  htlcHash: XOnly
  /** Distinct PTLC points across hops -- should equal the hop count. */
  distinctPtlcPoints: number
  /** Distinct HTLC hashes across hops -- should be 1. */
  distinctHtlcHashes: number
  settledInOrder: string[]
}

/**
 * Build the hop chain from the recipient backward, then settle it backward too.
 *
 * Points:  T_3 = z*G,  T_2 = (t_3 + b_3)*G,  T_1 = (t_2 + b_2)*G   (each normalised)
 * Secrets: t_3 = z,    t_2 = t_3 + b_3,      t_1 = t_2 + b_2       (each normalised)
 *
 * so the payee of hop i can always derive t_i from the t_{i+1} it just extracted
 * plus the blinding it was given -- and nobody except Alice can see that hop 1 and
 * hop 3 belong to one payment.
 */
export function runPtlc(hops: HopSpec[], z: bigint, message: string): PtlcRun {
  if (hops.length < 2) throw new Error('a routed payment needs at least two hops')
  const htlcHash = sha256(numTo32(mod(z)))

  // Secrets, from the recipient backward.
  const last = hops.length - 1
  const secrets: bigint[] = new Array(hops.length)
  secrets[last] = adaptorPoint(z).t
  for (let i = last - 1; i >= 0; i--) {
    // The payee of hop i holds hops[i+1].blinding; it adds it to what it extracted
    // from hop i+1 and re-normalises. Same computation Alice made when building T_i.
    secrets[i] = adaptorPoint(mod(secrets[i + 1] + hops[i + 1].blinding)).t
  }

  const results: HopResult[] = hops.map((h, i) => {
    const ad = adaptorPoint(secrets[i])
    const { publicKey } = normaliseSecret(h.payerSecretKey)
    const hopMsg = new TextEncoder().encode(`${message} [hop ${h.index}: ${h.payer} -> ${h.payee}]`)
    const pre = preSign(h.payerSecretKey, hopMsg, ad.Tx, { auxRand: numTo32(BigInt(i + 1)) })
    return {
      index: h.index,
      payer: h.payer,
      payee: h.payee,
      Tx: ad.Tx,
      secret: ad.t,
      htlcHash,
      publicKey,
      pre,
      preVerifies: preVerify(pre, publicKey, hopMsg, ad.Tx).ok,
      settled: false,
      extractedSecret: null,
      extractionMatches: false,
      signature: null,
    }
  })

  // Settlement runs BACKWARD: the last hop settles first, and each extraction is
  // what makes the hop before it settleable.
  const settledInOrder: string[] = []
  for (let i = last; i >= 0; i--) {
    const r = results[i]
    const { signature } = adapt(r.pre, r.secret)
    const ex = extract(r.pre, signature, r.Tx)
    r.signature = signature
    r.settled = true
    r.extractedSecret = ex.ok ? ex.t : null
    r.extractionMatches = ex.ok && ex.t === r.secret
    settledInOrder.push(`hop ${r.index} (${r.payer} -> ${r.payee})`)
  }

  const ptlcSet = new Set(results.map((r) => hex(r.Tx)))
  const htlcSet = new Set(results.map((r) => hex(r.htlcHash)))

  return {
    hops: results,
    z: mod(z),
    paymentPointX: adaptorPoint(z).Tx,
    htlcHash,
    distinctPtlcPoints: ptlcSet.size,
    distinctHtlcHashes: htlcSet.size,
    settledInOrder,
  }
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
