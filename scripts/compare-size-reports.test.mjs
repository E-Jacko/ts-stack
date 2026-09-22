import assert from 'node:assert/strict'
import { test } from 'node:test'

import { compareSizeReports } from './compare-size-reports.mjs'

function reports(raw, gzip = raw, brotli = raw) {
  return new Map([
    [
      '@bsv/example',
      {
        values: new Map([
          ['vite.raw', raw],
          ['vite.gzip', gzip],
          ['vite.brotli', brotli]
        ])
      }
    ]
  ])
}

test('size comparison accepts exact parity and reductions', () => {
  assert.equal(compareSizeReports(reports(10), reports(10)).violations.length, 0)
  assert.equal(compareSizeReports(reports(10), reports(9)).violations.length, 0)
})

test('size comparison rejects a single metric and aggregate regression', () => {
  const result = compareSizeReports(reports(10, 10, 10), reports(10, 11, 10))
  assert.deepEqual(
    result.violations.map(({ package: packageName, metric }) => [packageName, metric]),
    [
      ['@bsv/example', 'vite.gzip'],
      ['<aggregate>', 'all']
    ]
  )
})
