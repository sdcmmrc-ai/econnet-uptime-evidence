import { readFile } from 'node:fs/promises';

const repository = process.env.GITHUB_REPOSITORY;
const token = process.env.GITHUB_TOKEN;
const sha = process.argv[2];
const resultFile = process.argv[3];
if (!repository || !token || !sha || !resultFile) {
  throw new Error('usage: node scripts/post-status.mjs <sha> <publish-result.json>');
}
const result = JSON.parse(await readFile(resultFile, 'utf8'));
const response = await fetch(`https://api.github.com/repos/${repository}/statuses/${sha}`, {
  method: 'POST',
  headers: {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'User-Agent': 'econnet-uptime-evidence',
    'X-GitHub-Api-Version': '2022-11-28',
  },
  body: JSON.stringify({
    state: result.observation_state,
    context: 'external-uptime/observation',
    description: result.observation_status,
    target_url: `${process.env.GITHUB_SERVER_URL}/${repository}/actions/runs/${process.env.GITHUB_RUN_ID}`,
  }),
  signal: AbortSignal.timeout(15000),
});
if (!response.ok) throw new Error(`github-status:${response.status}`);
process.stdout.write('sanitized observation status recorded\n');
