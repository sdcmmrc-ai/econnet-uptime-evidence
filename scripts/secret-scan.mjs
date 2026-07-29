import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const patterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /gh[pousr]_[A-Za-z0-9]{30,}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /(?:password|secret|token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
  /\/home\/[A-Za-z0-9_-]+\//,
  /C:\\Users\\/i,
];

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

const findings = [];
for (const file of await walk('.')) {
  const content = await readFile(file, 'utf8');
  for (const pattern of patterns) if (pattern.test(content)) findings.push(`${file}: ${pattern}`);
}
if (findings.length) throw new Error(`secret scan findings:\n${findings.join('\n')}`);
process.stdout.write('secret scan passed (0 findings)\n');
