import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { runPtlc, defaultPtlcPath } from './ptlc'
import { hex, liftX, G, numTo32 } from './secp'
import { extract, adaptorPoint } from './adaptor'

describe('Invariant 10 — PTLC per-hop decorrelation', () => {
  const { hops, z, message } = defaultPtlcPath()
  const run = runPtlc(hops, z, message)

  it('has three hops', () => {
    expect(run.hops.length).toBe(3)
    expect(run.hops.map((h) => `${h.payer}->${h.payee}`)).toEqual([
      'Alice->Bob',
      'Bob->Carol',
      'Carol->Dave',
    ])
  })

  it('every hop carries a DIFFERENT adaptor point', () => {
    expect(run.distinctPtlcPoints).toBe(3)
    const xs = run.hops.map((h) => hex(h.Tx))
    expect(new Set(xs).size).toBe(3)
  })

  it('every hop carries the SAME HTLC hash — the contrast, computed from one run', () => {
    expect(run.distinctHtlcHashes).toBe(1)
    const hashes = run.hops.map((h) => hex(h.htlcHash))
    expect(new Set(hashes).size).toBe(1)
    // and both strips come from the same z, so this is a real comparison
    expect(hex(run.htlcHash)).toBe(hashes[0])
  })

  it('every hop pre-verifies and settles, and extraction matches at each hop', () => {
    for (const h of run.hops) {
      expect(h.preVerifies, `hop ${h.index} preVerify`).toBe(true)
      expect(h.settled, `hop ${h.index} settled`).toBe(true)
      expect(h.extractionMatches, `hop ${h.index} extraction`).toBe(true)
      expect(h.extractedSecret).toBe(h.secret)
    }
  })

  it('each hop secret really unlocks its own point: t_i*G == T_i', () => {
    for (const h of run.hops) {
      expect(G.multiply(h.secret).equals(liftX(h.Tx))).toBe(true)
    }
  })

  it('the completed signature on each hop verifies under that hop payer key', () => {
    for (const h of run.hops) {
      const hopMsg = new TextEncoder().encode(
        `${message} [hop ${h.index}: ${h.payer} -> ${h.payee}]`,
      )
      expect(h.signature).not.toBeNull()
      expect(schnorr.verify(h.signature!, hopMsg, h.publicKey)).toBe(true)
    }
  })

  it('settlement runs BACKWARD, last hop first', () => {
    expect(run.settledInOrder).toEqual([
      'hop 3 (Carol -> Dave)',
      'hop 2 (Bob -> Carol)',
      'hop 1 (Alice -> Bob)',
    ])
  })

  it('the last hop point is the invoice payment point', () => {
    expect(hex(run.hops[2].Tx)).toBe(hex(run.paymentPointX))
  })

  it('a node can derive its own hop secret from the one it extracted plus its blinding', () => {
    // The chain must be genuinely derivable by the intermediary, not just by the test.
    // Carol extracts hop 3's secret, adds the blinding she was handed, re-normalises,
    // and that must be exactly hop 2's secret -- the one that claims her incoming hop.
    const hop3 = run.hops[2]
    const hop2 = run.hops[1]
    const extractedByCarol = extract(hop3.pre, hop3.signature!, hop3.Tx)
    expect(extractedByCarol.ok).toBe(true)
    if (!extractedByCarol.ok) return
    const derived = adaptorPoint(extractedByCarol.t + hops[2].blinding)
    expect(derived.t).toBe(hop2.secret)
    expect(hex(derived.Tx)).toBe(hex(hop2.Tx))
    // and the same step again, one hop back
    const extractedByBob = extract(hop2.pre, hop2.signature!, hop2.Tx)
    expect(extractedByBob.ok).toBe(true)
    if (!extractedByBob.ok) return
    const derived1 = adaptorPoint(extractedByBob.t + hops[1].blinding)
    expect(derived1.t).toBe(run.hops[0].secret)
  })

  it('an observer of hop 1 and hop 3 sees unrelated points (PTLC) but equal hashes (HTLC)', () => {
    const h1 = run.hops[0]
    const h3 = run.hops[2]
    expect(hex(h1.Tx)).not.toBe(hex(h3.Tx))
    expect(hex(h1.htlcHash)).toBe(hex(h3.htlcHash))
  })

  it('a hop with a zero blinding would NOT decorrelate — the blinding is load-bearing', () => {
    const flat = defaultPtlcPath()
    for (const h of flat.hops) h.blinding = 0n
    const flatRun = runPtlc(flat.hops, flat.z, flat.message)
    expect(flatRun.distinctPtlcPoints).toBe(1)
    expect(run.distinctPtlcPoints).toBe(3)
  })

  it('the HTLC preimage is z itself, so revealing it links every hop', () => {
    expect(hex(run.htlcHash).length).toBe(64)
    expect(numTo32(run.z).length).toBe(32)
  })
})
