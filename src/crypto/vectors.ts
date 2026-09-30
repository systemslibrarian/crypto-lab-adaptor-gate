// Parse the vendored BIP-340 vector CSV. Imported as raw text so the browser and the
// test runner read exactly the same bytes -- there is no second copy to drift.

import csv from '../vectors/bip340-test-vectors.csv?raw'
import { fromHex } from './secp'

export type VectorClass = 'signable' | 'verify-only-accept' | 'verify-only-reject'

export interface Bip340Vector {
  index: number
  secretKey: Uint8Array | null
  publicKey: Uint8Array
  auxRand: Uint8Array | null
  message: Uint8Array
  signature: Uint8Array
  expected: boolean
  comment: string
  /** Which of the three classes this row belongs to. The UI shows all three. */
  cls: VectorClass
  messageLength: number
}

export const VECTOR_FILE_SHA256 =
  '34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d'

export function parseVectors(): Bip340Vector[] {
  const lines = csv.trim().split(/\r?\n/)
  const rows = lines.slice(1)
  return rows.map((line) => {
    const f = line.split(',')
    const secretKey = f[1] ? fromHex(f[1]) : null
    const auxRand = f[3] ? fromHex(f[3]) : null
    const expected = f[6] === 'TRUE'
    const signable = secretKey !== null && auxRand !== null
    const cls: VectorClass = signable
      ? 'signable'
      : expected
        ? 'verify-only-accept'
        : 'verify-only-reject'
    const message = fromHex(f[4] ?? '')
    return {
      index: Number(f[0]),
      secretKey,
      publicKey: fromHex(f[2] ?? ''),
      auxRand,
      message,
      signature: fromHex(f[5] ?? ''),
      expected,
      comment: f.slice(7).join(',').trim(),
      cls,
      messageLength: message.length,
    }
  })
}

export const BIP340_VECTORS: Bip340Vector[] = parseVectors()

/** Counts the UI prints, so no hand-authored number can drift from the file. */
export const VECTOR_COUNTS = {
  total: BIP340_VECTORS.length,
  signable: BIP340_VECTORS.filter((v) => v.cls === 'signable').length,
  verifyOnlyAccept: BIP340_VECTORS.filter((v) => v.cls === 'verify-only-accept').length,
  verifyOnlyReject: BIP340_VECTORS.filter((v) => v.cls === 'verify-only-reject').length,
}

/**
 * SHA-256 compression blocks the challenge tagged hash needs for a message of this
 * length: the input is 64 (two tag hashes) + 32 (r) + 32 (pk) + len(m), plus at least
 * 9 bytes of padding, rounded up to whole 64-byte blocks.
 */
export function challengeBlocks(messageLength: number): number {
  return Math.ceil((128 + messageLength + 9) / 64)
}
