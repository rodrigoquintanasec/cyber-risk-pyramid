// Dev helper: render a saved Morning Briefing JSON to the standalone HTML used by Preview / Print.
// Usage (from the repository root): node scripts/render-briefing.mjs briefing.json out.html
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { transformWithOxc } from 'vite'

const srcFile = fileURLToPath(new URL('../src/components/intel/briefingDoc.ts', import.meta.url))
const out = (await transformWithOxc(fs.readFileSync(srcFile, 'utf8'), 'briefingDoc.ts', { lang: 'ts' })).code
const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'brf-')), 'briefingDoc.mjs')
fs.writeFileSync(f, out)
const { briefingDocument } = await import(pathToFileURL(f).href)
const b = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
fs.writeFileSync(process.argv[3], briefingDocument(b))
console.log('html bytes', fs.statSync(process.argv[3]).size)
