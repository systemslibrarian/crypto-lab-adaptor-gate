import { describe, expect, it } from 'vitest'
import { completeVectorSet, fixtureEvidenceAgrees, type FixtureResult } from './evidence'

const expected = (): FixtureResult[] => [
  'peven-sumeven', 'peven-sumodd', 'podd-sumeven', 'podd-sumodd', 't-not-negated', 'deliberately-wrong',
].map(id => ({ id, deliberatelyWrong: id === 'deliberately-wrong', sMatches: id !== 'deliberately-wrong', accepted: true, extracted: true }))

describe('reference summaries require complete and correctly classified evidence', () => {
  it('refuses an empty, shortened, duplicated or out-of-range BIP-340 corpus', () => {
    const indices = Array.from({ length: 19 }, (_, i) => i)
    expect(completeVectorSet(indices)).toBe(true)
    for (const missing of [[], indices.slice(1), [...indices.slice(1), 1], [...indices.slice(1), 0.5], [...indices.slice(1), 19]]) {
      expect(completeVectorSet(missing)).toBe(false)
    }
  })
  it('accepts the five valid fixtures and the one scalar-mismatch control', () => {
    expect(fixtureEvidenceAgrees(expected())).toBe(true)
  })
  it('does not let an unexpected failure cancel an unexpected pass', () => {
    const rows = expected()
    rows[0].sMatches = false
    rows[5].sMatches = true
    // There is still exactly one failed row, but it is the wrong row.
    expect(rows.filter(row => !row.sMatches).length).toBe(1)
    expect(fixtureEvidenceAgrees(rows)).toBe(false)
  })
  it('requires the wrong-scalar control to retain successful verification and extraction', () => {
    for (const property of ['accepted', 'extracted'] as const) {
      const rows = expected()
      rows[5][property] = false
      expect(fixtureEvidenceAgrees(rows)).toBe(false)
    }
  })
  it('rejects missing, duplicated and mislabelled fixture evidence', () => {
    expect(fixtureEvidenceAgrees([])).toBe(false)
    expect(fixtureEvidenceAgrees(expected().slice(1))).toBe(false)
    const rows = expected()
    rows[0].id = rows[1].id
    expect(fixtureEvidenceAgrees(rows)).toBe(false)
    const flags = expected()
    flags[0].deliberatelyWrong = true
    expect(fixtureEvidenceAgrees(flags)).toBe(false)
  })
})
