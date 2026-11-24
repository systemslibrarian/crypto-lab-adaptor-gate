import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { preSign, adapt, extract, adaptorPoint, concat64 } from './adaptor'
import { N, G, mod, numTo32, normaliseSecret, liftX, invModN } from './secp'

const sk = numTo32(17n)
const msg = new TextEncoder().encode('student review: public teaching inputs')

describe('student review: point identity and public nonce limits', () => {
  it('rejects the opposite point even though its x-only encoding matches', () => {
    for (let t = 1n; t <= 12n; t++) {
      const ad = adaptorPoint(t)
      const pre = preSign(sk, msg, ad.Tx)
      const wrong = adapt(pre, N - ad.t)
      expect(schnorr.verify(wrong.signature, msg, normaliseSecret(sk).publicKey)).toBe(false)
      expect(G.multiply(N - ad.t).x).toBe(liftX(ad.Tx).x)
      expect(G.multiply(N - ad.t).equals(liftX(ad.Tx))).toBe(false)
      expect(extract(pre, wrong.signature, ad.Tx).ok).toBe(false)
      const correct = extract(pre, adapt(pre, ad.t).signature, ad.Tx)
      expect(correct.ok).toBe(true)
    }
  })
  it('allows the signature-scalar zero boundary in the extraction equation', () => {
    // Algebraic boundary fixture, not a claim of a valid signed message. The
    // caller separately verifies signatures; BIP-340 permits s in [0, n-1].
    const ad = adaptorPoint(3n)
    const pre = preSign(sk, msg, ad.Tx)
    pre.sHat = pre.parity === 'even' ? mod(-ad.t) : ad.t
    const result = extract(pre, concat64(pre.sumX, 0n), ad.Tx)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.t).toBe(ad.t)
  })
  it('independently recovers the key from one deliberately public H(m) nonce', () => {
    const ad = adaptorPoint(11n)
    const pre = preSign(sk, msg, ad.Tx, { mode: 'naive' })
    const sha = (x: Uint8Array) => createHash('sha256').update(x).digest()
    const tag = sha(new TextEncoder().encode('BIP0340/nonce'))
    const raw = mod(BigInt('0x' + sha(Buffer.concat([tag, tag, msg])).toString('hex')))
    const normalised = G.multiply(raw).y % 2n === 0n ? raw : N - raw
    const adjusted = pre.parity === 'even' ? normalised : N - normalised
    const recovered = mod((pre.sHat - adjusted) * invModN(pre.e))
    expect(recovered).toBe(normaliseSecret(sk).d)
  })
})
