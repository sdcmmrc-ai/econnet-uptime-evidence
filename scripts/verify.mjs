import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateEvidence } from './lib.mjs';

export async function verifyFile(file, {
  publicKeyFile = resolve('keys/public-key.pem'),
  previousFile = null,
  requireFresh = true,
  now = new Date(),
} = {}) {
  const record = JSON.parse(await readFile(file, 'utf8'));
  const publicKeyPem = await readFile(publicKeyFile, 'utf8');
  const previousRecord = previousFile ? JSON.parse(await readFile(previousFile, 'utf8')) : null;
  validateEvidence(record, { publicKeyPem, previousRecord, requireFresh, now });
  return record;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2];
  if (!file) throw new Error('usage: node scripts/verify.mjs <evidence.json> [previous.json]');
  const record = await verifyFile(file, { previousFile: process.argv[3] || null });
  process.stdout.write(`verified sequence ${record.sequence} (${record.current_status})\n`);
}
