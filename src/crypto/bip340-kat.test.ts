// GATE 1 -- the library check, pinned so it keeps holding.
//
// Nothing in this lab is allowed to be built on @noble/curves until the library has
// been checked against a PUBLISHED vector set, and not against its own README. A
// wrapper that is subtly wrong looks exactly like a lab that is subtly wrong, and the
// search for the bug goes to the wrong file. So: all 19 rows of BIP-340's own
// test-vectors.csv, verify AND deterministic sign, on every run.

import { describe, it, expect } from 'vitest'
import { sha256 } from '@noble/hashes/sha2.js'
import { schnorr } from '@noble/curves/secp256k1.js'
import csvRaw from '../vectors/bip340-test-vectors.csv?raw'
import { BIP340_VECTORS, VECTOR_COUNTS, VECTOR_FILE_SHA256, challengeBlocks } from './vectors'
import { hex } from './secp'

describe('BIP-340 vendored vector file', () => {
  it('is the file whose provenance is recorded, byte for byte', () => {
    // If a re-fetch changes the file, this fails rather than silently re-baselining.
    expect(hex(sha256(new TextEncoder().encode(csvRaw)))).toBe(VECTOR_FILE_SHA256)
  })

  it('has the shape PROVENANCE.md claims, measured not assumed', () => {
    expect(VECTOR_COUNTS.total).toBe(19)
    expect(VECTOR_COUNTS.signable).toBe(8)
    expect(VECTOR_COUNTS.verifyOnlyAccept).toBe(1)
    expect(VECTOR_COUNTS.verifyOnlyReject).toBe(10)
    expect(VECTOR_COUNTS.signable + VECTOR_COUNTS.verifyOnlyAccept + VECTOR_COUNTS.verifyOnlyReject).toBe(
      VECTOR_COUNTS.total,
    )
    expect(BIP340_VECTORS.filter((v) => v.cls === 'signable').map((v) => v.index)).toEqual([
      0, 1, 2, 3, 15, 16, 17, 18,
    ])
    expect(BIP340_VECTORS.map((v) => v.messageLength)).toEqual([
      32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 0, 1, 17, 100,
    ])
  })

  it('row 18 is the only row reaching a fourth challenge-hash block', () => {
    // The brief's conclusion, restated as the measurement that actually supports it.
    // EVERY row is multi-block: the tagged-hash prefix alone is 128 bytes. What makes
    // row 18 unique is reaching block four.
    const blocks = BIP340_VECTORS.map((v) => challengeBlocks(v.messageLength))
    expect(Math.min(...blocks)).toBe(3) // no row fits in fewer than three
    const fourPlus = BIP340_VECTORS.filter((v) => challengeBlocks(v.messageLength) >= 4)
    expect(fourPlus.map((v) => v.index)).toEqual([18])
  })
})

describe('GATE 1: @noble/curves against BIP-340 published vectors', () => {
  it.each(BIP340_VECTORS.map((v) => [v.index, v.cls, v.comment || '(no comment)', v] as const))(
    'row %i (%s) verify matches the published result — %s',
    (_i, _c, _cm, v) => {
      let got = false
      try {
        got = schnorr.verify(v.signature, v.message, v.publicKey)
      } catch {
        got = false
      }
      expect(got).toBe(v.expected)
    },
  )

  it.each(BIP340_VECTORS.filter((v) => v.cls === 'signable').map((v) => [v.index, v] as const))(
    'row %i deterministic sign is byte-exact against the published signature',
    (_i, v) => {
      const sig = schnorr.sign(v.message, v.secretKey!, v.auxRand!)
      expect(hex(sig)).toBe(hex(v.signature))
    },
  )
})
