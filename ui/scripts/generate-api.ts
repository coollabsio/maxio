import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [input = 'src/api/generated/openapi.json', output = 'src/api/generated'] = Bun.argv.slice(2)
const source = await Bun.file(input).text()
const document = JSON.parse(source)
const contractId = document?.info?.version
if (typeof contractId !== 'string' || !contractId) {
  throw new Error('OpenAPI info.version must contain the API contract ID.')
}

const temporary = await mkdtemp(join(tmpdir(), 'maxio-api-'))
const temporaryInput = join(temporary, 'openapi.json')
await Bun.write(temporaryInput, source)
await rm(output, { recursive: true, force: true })
await mkdir(output, { recursive: true })
const generated = Bun.spawnSync([
  process.execPath,
  'x',
  'openapi-ts',
  '-i',
  temporaryInput,
  '-o',
  output,
  '-c',
  '@hey-api/client-fetch',
  '-s',
])
await rm(temporary, { recursive: true, force: true })
if (!generated.success) {
  process.stderr.write(generated.stderr)
  process.exit(generated.exitCode)
}

await Bun.write(join(output, 'openapi.json'), source)
await Bun.write(
  join(output, 'contract.ts'),
  `// Generated from OpenAPI info.version. Do not edit.\nexport const CONTRACT_ID = ${JSON.stringify(contractId)} as const\n`,
)
