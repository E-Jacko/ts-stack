import assert from 'node:assert/strict'
import { test } from 'node:test'

import { comparePerformanceReports } from './compare-performance-reports.mjs'

function report(first, second = first) {
  return {
    benchmark: 'example',
    payloadBytes: 1024,
    measurements: {
      first: { medianMs: first },
      second: { medianMs: second }
    }
  }
}

test('performance comparison accepts exact parity and per-case improvements', () => {
  assert.equal(comparePerformanceReports(report(10), report(10)).violations.length, 0)
  assert.equal(comparePerformanceReports(report(10), report(9)).violations.length, 0)
})

test('performance comparison rejects one slower case and aggregate growth', () => {
  const comparison = comparePerformanceReports(report(10, 10), report(10, 11))
  assert.deepEqual(
    comparison.violations.map(({ name }) => name),
    ['second', '<aggregate>']
  )
})
