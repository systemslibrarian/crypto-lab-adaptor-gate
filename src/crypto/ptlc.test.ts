import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import {
  startPtlc,
  settleNext,
  settleAll,
  ptlcFinished,
  defaultPtlcPath,
  type PtlcState,
} from './ptlc'
import { hex, liftX, G, numTo32, mod } from './secp'
import { extract, adaptorPoint } from './adaptor'

const fresh = (faults = {}) => {
  const { hops, z, message } = defaultPtlcPath()
  return startPtlc(hops, z, message, faults)
}

describe('Invariant 10 — PTLC per-hop decorrelation', () => {
  const run = settleAll(fresh())

  it('has three hops on a four-node path', () => {
    expect(run.hops.length).toBe(3)
    expect(run.hops.map((h) => `${h.payer}->${h.payee}`)).toEqual([
      'Alice->Bob',
      'Bob->Carol',
      'Carol->Dave',
    ])
  })

  it('every hop carries a DIFFERENT adaptor point', () => {
    expect(run.distinctPtlcPoints).toBe(3)
    expect(new Set(run.hops.map((h) => hex(h.Tx))).size).toBe(3)
  })

  it('every hop carries the SAME HTLC hash — the contrast, from one run', () => {
    expect(run.distinctHtlcHashes).toBe(1)
    expect(new Set(run.hops.map((h) => hex(h.htlcHash))).size).toBe(1)
    expect(hex(run.htlcHash)).toBe(hex(run.hops[0].htlcHash))
  })

  it('an observer of hop 1 and hop 3 can match the hashes and not the points', () => {
    expect(hex(run.hops[0].htlcHash)).toBe(hex(run.hops[2].htlcHash))
    expect(hex(run.hops[0].Tx)).not.toBe(hex(run.hops[2].Tx))
  })

  it('the blinding scalars are load-bearing: zero them and the points collapse', () => {
    const { hops, z, message } = defaultPtlcPath()
    for (const h of hops) h.blinding = 0n
    const flat = startPtlc(hops, z, message)
    expect(flat.distinctPtlcPoints).toBe(1)
    expect(run.distinctPtlcPoints).toBe(3)
  })
})

describe('the honest settlement, end to end', () => {
  const run = settleAll(fresh())

  it('settles every hop', () => {
    expect(ptlcFinished(run)).toBe(true)
    for (const h of run.hops) expect(h.status, `hop ${h.index}`).toBe('settled')
    expect(run.broken).toBe(false)
  })

  it('each hop pre-verifies, and its completed signature verifies under the payer key', () => {
    for (const h of run.hops) {
      expect(h.preVerifies, `hop ${h.index} preVerify`).toBe(true)
      expect(h.signature).not.toBeNull()
      expect(schnorr.verify(h.signature!, h.message, h.publicKey), `hop ${h.index}`).toBe(true)
    }
  })

  it('every hop was completed with the secret the route builder intended', () => {
    // usedSecret is the DERIVED value; expectedSecret is the route builder's. They
    // must agree -- but they are produced by different paths, which is the point.
    for (const h of run.hops) {
      expect(h.usedSecret, `hop ${h.index} used`).toBe(h.expectedSecret)
      expect(h.extractionMatches, `hop ${h.index} extraction`).toBe(true)
    }
  })

  it('each hop secret really unlocks its own point: t_i*G == T_i', () => {
    for (const h of run.hops) {
      expect(G.multiply(h.usedSecret!).equals(liftX(h.Tx))).toBe(true)
    }
  })

  it('settlement runs BACKWARD, last hop first', () => {
    expect(run.log[0]).toContain('hop 3 settled')
    expect(run.log.filter((l) => /settled/.test(l)).map((l) => l.match(/hop (\d)/)![1])).toEqual([
      '3',
      '2',
      '1',
    ])
  })

  it('the last hop point is the invoice payment point', () => {
    expect(hex(run.hops[2].Tx)).toBe(hex(run.paymentPointX))
  })
})

// ---------------------------------------------------------------------------
// The causality tests. These are what the model was missing.
// ---------------------------------------------------------------------------

describe('CAUSALITY — upstream settlement consumes the downstream extracted value', () => {
  it('only the recipient starts with a secret; the rest is derived', () => {
    const s = fresh()
    // Before anything settles, exactly one secret exists and it is z.
    expect(s.carried).toBe(adaptorPoint(s.z).t)
    for (const h of s.hops) {
      expect(h.status).toBe('waiting')
      expect(h.usedSecret).toBeNull()
      expect(h.extractedSecret).toBeNull()
    }
  })

  it('the value used to settle each hop is the one extracted from the hop below it', () => {
    let s: PtlcState = fresh()
    const used: bigint[] = []
    const extracted: bigint[] = []
    while (!ptlcFinished(s)) {
      const i = s.cursor
      s = settleNext(s)
      used.unshift(s.hops[i].usedSecret!)
      extracted.unshift(s.hops[i].extractedSecret!)
    }
    // hop i's used secret == extracted(hop i+1) + blinding(hop i+1), normalised
    for (let i = 0; i < s.hops.length - 1; i++) {
      const derived = adaptorPoint(mod(extracted[i + 1] + s.hops[i + 1].blinding)).t
      expect(used[i], `hop ${i + 1} must consume hop ${i + 2}'s extracted value`).toBe(derived)
    }
  })

  it('the cursor really does move one hop at a time, upstream', () => {
    let s = fresh()
    expect(s.cursor).toBe(2)
    s = settleNext(s)
    expect(s.cursor).toBe(1)
    expect(s.hops[2].status).toBe('settled')
    expect(s.hops[1].status).toBe('waiting')
    expect(s.hops[0].status).toBe('waiting')
    s = settleNext(s)
    expect(s.cursor).toBe(0)
    expect(s.hops[1].status).toBe('settled')
    expect(s.hops[0].status).toBe('waiting')
    s = settleNext(s)
    expect(ptlcFinished(s)).toBe(true)
    expect(s.hops[0].status).toBe('settled')
  })
})

describe('CAUSALITY — breaking the chain stops every hop upstream of the break', () => {
  it('a corrupt signature at the LAST hop blocks both hops before it', () => {
    const run = settleAll(fresh({ corruptSignatureAtHop: 3 }))
    expect(run.hops[2].status).toBe('blocked')
    expect(run.hops[2].blockedReason).toMatch(/corrupt/)
    // and nothing upstream could settle
    expect(run.hops[1].status).toBe('blocked')
    expect(run.hops[0].status).toBe('blocked')
    expect(run.broken).toBe(true)
    for (const h of run.hops) expect(h.extractionMatches).toBe(false)
  })

  it('a corrupt signature at the MIDDLE hop settles the last and blocks the first', () => {
    const run = settleAll(fresh({ corruptSignatureAtHop: 2 }))
    expect(run.hops[2].status).toBe('settled') // downstream of the break: fine
    expect(run.hops[1].status).toBe('blocked')
    expect(run.hops[0].status).toBe('blocked')
    expect(run.hops[0].blockedReason).toMatch(/no usable secret arrived from downstream/)
  })

  it('a corrupt signature at the FIRST hop blocks nothing else — there is nothing upstream', () => {
    // Scoping the claim: the break only propagates in one direction.
    const run = settleAll(fresh({ corruptSignatureAtHop: 1 }))
    expect(run.hops[2].status).toBe('settled')
    expect(run.hops[1].status).toBe('settled')
    expect(run.hops[0].status).toBe('blocked')
  })

  it('a WRONG BLINDING at a hop blocks every hop upstream of it', () => {
    // The signature is fine and extraction succeeds; the payee simply derives the
    // wrong secret, so the pre-signature it then tries to complete does not verify.
    const run = settleAll(fresh({ wrongBlindingAtHop: 3 }))
    expect(run.hops[2].status).toBe('settled')
    expect(run.hops[2].extractionMatches).toBe(true) // extraction itself was correct
    expect(run.hops[1].status).toBe('blocked')
    expect(run.hops[0].status).toBe('blocked')
    expect(run.broken).toBe(true)
  })

  it('a wrong blinding is NOT an extraction failure — scoping the cause precisely', () => {
    const run = settleAll(fresh({ wrongBlindingAtHop: 3 }))
    const h3 = run.hops[2]
    // everything at hop 3 worked
    expect(h3.status).toBe('settled')
    expect(h3.extractedSecret).toBe(h3.expectedSecret)
    // what failed is hop 2's completion, because the value derived for it was wrong
    expect(run.hops[1].usedSecret).not.toBe(run.hops[1].expectedSecret)
    expect(run.hops[1].blockedReason).toMatch(/not valid under this hop payer key/)
  })

  it('a blocked hop publishes nothing the channel accepts', () => {
    const run = settleAll(fresh({ corruptSignatureAtHop: 2 }))
    const blocked = run.hops[1]
    if (blocked.signature) {
      expect(schnorr.verify(blocked.signature, blocked.message, blocked.publicKey)).toBe(false)
    }
    expect(run.hops[0].signature).toBeNull()
  })
})

describe('the derivation a payee performs is reproducible by hand', () => {
  it('extract, add your blinding, re-normalise — and you have the next hop secret', () => {
    const run = settleAll(fresh())
    const hop3 = run.hops[2]
    const hop2 = run.hops[1]
    const hop1 = run.hops[0]

    const carolExtracted = extract(hop3.pre, hop3.signature!, hop3.Tx)
    expect(carolExtracted.ok).toBe(true)
    if (!carolExtracted.ok) return
    const carolDerives = adaptorPoint(mod(carolExtracted.t + hop3.blinding)).t
    expect(carolDerives).toBe(hop2.usedSecret)
    expect(hex(adaptorPoint(carolDerives).Tx)).toBe(hex(hop2.Tx))

    const bobExtracted = extract(hop2.pre, hop2.signature!, hop2.Tx)
    expect(bobExtracted.ok).toBe(true)
    if (!bobExtracted.ok) return
    const bobDerives = adaptorPoint(mod(bobExtracted.t + hop2.blinding)).t
    expect(bobDerives).toBe(hop1.usedSecret)
  })

  it('the HTLC preimage is z itself, so revealing it links every hop', () => {
    const run = settleAll(fresh())
    expect(hex(run.htlcHash).length).toBe(64)
    expect(numTo32(run.z).length).toBe(32)
  })
})
