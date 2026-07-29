import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  SCHEMA_VERSION,
  PRODUCER,
  advanceCandidate,
  calculateEvidenceFingerprint,
  decidePublication,
  decodeObservationStatus,
  encodeObservationStatus,
  incidentId,
  signEvidence,
  timestamp,
  uptimeBasisPoints,
  validateEvidence,
  validateMaintenance,
} from './lib.mjs';
import { probeAll } from './probe.mjs';

const CONTEXT = 'external-uptime/observation';

function argument(name, fallback = null) {
  const prefix = `--${name}=`;
  const value = process.argv.find((item) => item.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

async function readJson(file, fallback = null) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

async function githubRequest(pathname, token) {
  const response = await fetch(`https://api.github.com${pathname}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'econnet-uptime-evidence',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`github-api:${response.status}`);
  return response.json();
}

async function priorCandidate({ repository, evidenceSha, token }) {
  if (!repository || !evidenceSha || !token) return null;
  const statuses = await githubRequest(`/repos/${repository}/commits/${evidenceSha}/statuses?per_page=100`, token);
  const match = statuses.find((status) => status.context === CONTEXT);
  return match ? decodeObservationStatus(match.description) : null;
}

function updateEndpointState(endpoint, previousEndpoint, candidate, incident) {
  const failed = endpoint.failure_category !== 'none';
  const sameFailure = previousEndpoint?.failure_category === endpoint.failure_category;
  endpoint.consecutive_failures = failed ? (sameFailure ? previousEndpoint.consecutive_failures + 1 : candidate.failures || 1) : 0;
  endpoint.consecutive_successes = failed ? 0 : Math.max(candidate.successes, (previousEndpoint?.consecutive_successes || 0) + 1);
  if (incident && failed) {
    endpoint.incident_id_hash = incident.incident_id_hash;
    endpoint.incident_started_at = incident.started_at;
  } else {
    endpoint.incident_id_hash = null;
    endpoint.incident_started_at = null;
  }
  return endpoint;
}

async function incidentHistory(stateRoot) {
  const directory = join(stateRoot, 'evidence', 'incidents');
  try {
    const files = (await readdir(directory)).filter((file) => file.endsWith('.json')).sort();
    return Promise.all(files.map((file) => readJson(join(directory, file))));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

export async function produce({
  stateRoot,
  outputFile,
  privateKeyPem,
  publicKeyPem,
  observation,
  prior = null,
  now = new Date(),
}) {
  const currentFile = join(stateRoot, 'evidence', 'current.json');
  const previous = await readJson(currentFile);
  if (previous) {
    validateEvidence(previous, { publicKeyPem, requireFresh: false });
  }
  const maintenance = await readJson(resolve('maintenance.json'));
  validateMaintenance(maintenance, now);
  const candidate = advanceCandidate(prior, observation.category);
  const generatedAt = timestamp(now);
  const hourlyDue = !previous || now.getTime() - Date.parse(previous.generated_at) >= 55 * 60 * 1000;
  const decision = previous
    ? decidePublication(previous.current_status, candidate, { hourlyDue })
    : {
      publish: true,
      transition: false,
      confirmedStatus: observation.category === 'none' ? 'healthy' : 'unknown',
      reason: 'initial-checkpoint',
    };

  const result = {
    publish: decision.publish,
    reason: decision.reason,
    observation_status: encodeObservationStatus(candidate),
    observation_state: observation.category === 'none' ? 'success' : 'failure',
    evidence_fingerprint: previous?.evidence_fingerprint || null,
  };
  if (!decision.publish) {
    await writeFile(outputFile, `${JSON.stringify(result)}\n`, { mode: 0o600 });
    return result;
  }

  let lastIncident = previous?.last_incident || null;
  if (decision.confirmedStatus === 'down' || (decision.confirmedStatus === 'degraded' && observation.category !== 'response_slow')) {
    const startedAt = previous?.current_status === decision.confirmedStatus && lastIncident?.recovered_at === null
      ? lastIncident.started_at
      : generatedAt;
    lastIncident = {
      incident_id_hash: incidentId(observation.category, startedAt),
      failure_category: observation.category,
      started_at: startedAt,
      recovered_at: null,
    };
  } else if (decision.confirmedStatus === 'healthy' && lastIncident?.recovered_at === null) {
    lastIncident = { ...lastIncident, recovered_at: generatedAt };
  }

  const previousEndpoints = Object.fromEntries((previous?.endpoint_results || []).map((item) => [item.endpoint_category, item]));
  const endpointResults = observation.endpoint_results.map((endpoint) =>
    updateEndpointState(structuredClone(endpoint), previousEndpoints[endpoint.endpoint_category], candidate, lastIncident?.recovered_at === null ? lastIncident : null));

  const incidents = (await incidentHistory(stateRoot)).filter(Boolean);
  if (lastIncident && !incidents.some((item) => item.incident_id_hash === lastIncident.incident_id_hash)) {
    incidents.push(lastIncident);
  }
  const endMs = now.getTime();
  const record = {
    schema_version: SCHEMA_VERSION,
    sequence: (previous?.sequence || 0) + 1,
    generated_at: generatedAt,
    fresh_until: timestamp(new Date(endMs + 80 * 60 * 1000)),
    producer: PRODUCER,
    observation_window: {
      started_at: observation.started_at,
      ended_at: observation.ended_at,
    },
    current_status: decision.confirmedStatus,
    last_success_at: observation.category === 'none' ? generatedAt : (previous?.last_success_at || null),
    last_incident: lastIncident,
    uptime_24h_basis_points: uptimeBasisPoints(incidents, new Date(endMs - 86400000), now),
    uptime_30d_basis_points: uptimeBasisPoints(incidents, new Date(endMs - 30 * 86400000), now),
    endpoint_results: endpointResults,
    previous_evidence_fingerprint: previous?.evidence_fingerprint || null,
    evidence_fingerprint: '0'.repeat(64),
    authentication: {
      scheme: 'ed25519',
      key_id: 'econnet-uptime-ed25519-2026-01',
      signature_domain: SCHEMA_VERSION,
      signature: 'A'.repeat(86) + '==',
    },
  };
  const signed = signEvidence(record, privateKeyPem);
  validateEvidence(signed, { publicKeyPem, previousRecord: previous, now });

  const safeTime = generatedAt.replaceAll(':', '').replaceAll('-', '');
  const checkpoint = join(stateRoot, 'evidence', 'checkpoints', `${safeTime}-sequence-${signed.sequence}.json`);
  await mkdir(join(stateRoot, 'evidence', 'checkpoints'), { recursive: true });
  await mkdir(join(stateRoot, 'evidence', 'incidents'), { recursive: true });
  const serialized = `${JSON.stringify(signed, null, 2)}\n`;
  await writeFile(currentFile, serialized);
  await writeFile(checkpoint, serialized);
  if (lastIncident && decision.transition) {
    await writeFile(
      join(stateRoot, 'evidence', 'incidents', `${lastIncident.incident_id_hash}.json`),
      `${JSON.stringify(lastIncident, null, 2)}\n`,
    );
  }
  result.evidence_fingerprint = calculateEvidenceFingerprint(signed);
  result.sequence = signed.sequence;
  result.current_status = signed.current_status;
  await writeFile(outputFile, `${JSON.stringify(result)}\n`, { mode: 0o600 });
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const stateRoot = resolve(argument('state-root', '.'));
  const outputFile = resolve(argument('output', '.publish-result.json'));
  const privateKeyPem = process.env.UPTIME_ED25519_PRIVATE_KEY;
  if (!privateKeyPem) throw new Error('UPTIME_ED25519_PRIVATE_KEY is required');
  const publicKeyPem = await readFile(resolve('keys/public-key.pem'), 'utf8');
  const observation = await probeAll();
  const prior = await priorCandidate({
    repository: process.env.GITHUB_REPOSITORY,
    evidenceSha: process.env.EVIDENCE_SHA,
    token: process.env.GITHUB_TOKEN,
  });
  const result = await produce({ stateRoot, outputFile, privateKeyPem, publicKeyPem, observation, prior });
  process.stdout.write(`publication=${result.publish}; reason=${result.reason}; observation=${observation.category}\n`);
}
