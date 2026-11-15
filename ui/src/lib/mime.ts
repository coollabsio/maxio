import { lookup } from 'mrmime'

const OVERRIDES: Record<string, string> = {
  // extensionless config files, matched on the full lowercased filename
  dockerfile: 'text/plain',
  makefile: 'text/plain',
  '.gitignore': 'text/plain',
  '.dockerignore': 'text/plain',
  '.env': 'text/plain',
  // mrmime mistypes these (e.g. .ts -> video/mp2t); force text
  ts: 'text/plain',
  tsx: 'text/plain',
  jsx: 'text/plain',
  rs: 'text/x-rust',
  // source / scripts / config mrmime has no entry for
  sh: 'application/x-sh',
  bash: 'application/x-sh',
  zsh: 'application/x-sh',
  py: 'text/x-python',
  rb: 'text/x-ruby',
  go: 'text/x-go',
  c: 'text/x-c',
  h: 'text/x-c',
  cpp: 'text/x-c++',
  cc: 'text/x-c++',
  java: 'text/x-java',
  php: 'text/x-php',
  scss: 'text/plain',
  less: 'text/plain',
  sql: 'text/plain',
  ini: 'text/plain',
  conf: 'text/plain',
  cfg: 'text/plain',
  env: 'text/plain',
  properties: 'text/plain',
  jsonc: 'application/json',
}

export function guessContentType(filename: string): string | undefined {
  const name = filename.toLowerCase()
  if (name in OVERRIDES) return OVERRIDES[name]
  const dot = name.lastIndexOf('.')
  const ext = dot >= 0 ? name.slice(dot + 1) : name
  return OVERRIDES[ext] ?? lookup(name)
}
