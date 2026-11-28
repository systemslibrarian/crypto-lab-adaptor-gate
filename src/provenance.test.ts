import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

describe('adaptor-signature research chronology', () => {
  it('preserves the 2021 to 2022 to 2024 chronology and concrete-model boundary', () => {
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    const lesson = readFileSync(new URL('./ui/honesty.ts', import.meta.url), 'utf8')

    expect(readme).toMatch(/Aumayr[\s\S]+INDOCRYPT 2022[\s\S]+Gerhart/)
    expect(lesson).toMatch(/Aumayr[\s\S]+Dai[\s\S]+Gerhart/)

    expect(readme).toContain('not every generic security notion')
    expect(lesson).toMatch(/This lab does not prove every '[\s\S]*generic definition/)
    expect(lesson).toContain('10.1007/978-3-031-22912-1_3')
  })
})
