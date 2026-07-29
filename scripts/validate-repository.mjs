import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const required = [
  '.github/workflows/external-uptime.yml',
  'README.md',
  'SECURITY.md',
  'docs/architecture.md',
  'docs/uptimerobot-setup.md',
  'docs/incident-runbook.md',
  'schemas/external-uptime.schema.json',
  'scripts/lib.mjs',
  'scripts/probe.mjs',
  'scripts/publish.mjs',
  'scripts/post-status.mjs',
  'scripts/verify.mjs',
  'tests/external-uptime.test.mjs',
  'keys/public-key.pem',
  'maintenance.json',
];
for (const file of required) await readFile(resolve(file));

for (const file of ['maintenance.json', 'schemas/external-uptime.schema.json', 'package.json']) {
  JSON.parse(await readFile(resolve(file), 'utf8'));
}

const workflow = await readFile(resolve('.github/workflows/external-uptime.yml'), 'utf8');
const assertions = [
  /cron:\s*['"]7,17,27,37,47,57 \* \* \* \*['"]/,
  /workflow_dispatch:/,
  /runs-on:\s*ubuntu-latest/,
  /contents:\s*write/,
  /statuses:\s*write/,
  /cancel-in-progress:\s*false/,
];
if (assertions.some((pattern) => !pattern.test(workflow))) {
  throw new Error('workflow policy validation failed');
}
if (/actions\/upload-artifact|actions\/cache|larger runner|UPTIMEROBOT/i.test(workflow)) {
  throw new Error('workflow contains a prohibited paid or retained resource');
}

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path));
    else output.push(path);
  }
  return output;
}
const files = await walk('.');
for (const file of files) {
  const bytes = await readFile(file);
  if (bytes.includes(Buffer.from('\r\n'))) throw new Error(`non-canonical CRLF: ${file}`);
}
process.stdout.write(`repository validation passed (${files.length} files)\n`);
