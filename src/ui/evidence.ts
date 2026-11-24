/** Completeness is checked against the pinned corpus, separately from agreement. */
export function completeVectorSet(indices: number[]): boolean {
  return indices.length === 19 && new Set(indices).size === 19 &&
    indices.every(i => Number.isInteger(i) && i >= 0 && i < 19)
}

const FIXTURE_IDS = ['peven-sumeven', 'peven-sumodd', 'podd-sumeven', 'podd-sumodd', 't-not-negated', 'deliberately-wrong']

export interface FixtureResult {
  id: string
  deliberatelyWrong: boolean
  sMatches: boolean
  accepted: boolean
  extracted: boolean
}

export function fixtureEvidenceAgrees(rows: FixtureResult[]): boolean {
  const ids = new Set(rows.map(row => row.id))
  return rows.length === FIXTURE_IDS.length && ids.size === FIXTURE_IDS.length &&
    FIXTURE_IDS.every(id => ids.has(id)) && rows.every(row =>
      row.deliberatelyWrong === (row.id === 'deliberately-wrong') &&
      row.sMatches === !row.deliberatelyWrong && row.accepted && row.extracted)
}
