import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { FileRevocationStore } from '../../modules/file-revocation-store'

const SERIAL = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
const OUTPOINT = `${'a'.repeat(64)}.0`
const SECRET = 'b'.repeat(64)

describe('FileRevocationStore security boundaries', () => {
  let directory: string
  let path: string

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'simple-revocation-store-'))
    path = join(directory, 'records.json')
  })

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true })
  })

  it('owns saved and loaded transaction bytes', async () => {
    const store = new FileRevocationStore(path)
    const record = { secret: SECRET, outpoint: OUTPOINT, beef: [1, 2, 3] }
    await store.save(SERIAL, record)
    record.beef[0] = 255

    const loaded = await store.load(SERIAL)
    expect(loaded).toEqual({ secret: SECRET, outpoint: OUTPOINT, beef: [1, 2, 3] })
    loaded?.beef.splice(0)
    await expect(store.load(SERIAL)).resolves.toMatchObject({ beef: [1, 2, 3] })
  })

  it('fails closed on malformed persisted secrets and transaction bytes', async () => {
    writeFileSync(
      path,
      JSON.stringify({ [SERIAL]: { secret: 'not-hex', outpoint: OUTPOINT, beef: [999] } }),
      { mode: 0o600 }
    )
    const store = new FileRevocationStore(path)

    await expect(store.load(SERIAL)).rejects.toThrow('Stored revocation record is invalid')
    await expect(store.findByOutpoint(OUTPOINT)).rejects.toThrow(
      'Stored revocation record is invalid'
    )
  })
})
