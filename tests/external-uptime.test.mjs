import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  SCHEMA_VERSION,
  advanceCandidate,
  calculateEvidenceFingerprint,
  canonicalize,
  certificateFailure,
  classifyObservation,
  decidePublication,
  groupIncident,
  incidentId,
  monitorId,
  signEvidence,
  timestamp,
  validateEvidence,
  validateMaintenance,
} from '../scripts/lib.mjs';
import { ROUTES, probeAll, probeDns, probeRoute, probeTls } from '../scripts/probe.mjs';
import { produce } from '../scripts/publish.mjs';

const keys = generateKeyPairSync('ed25519');
const privateKeyPem = keys.privateKey.export({ format: 'pem', type: 'pkcs8' });
const publicKeyPem = keys.publicKey.export({ format: 'pem', type: 'spki' });
const NOW = new Date('2026-07-29T00:00:00Z');

function endpoint(category, failure = 'none') {
  const route = category.startsWith('route_');
  return {
    monitor_id_hash: monitorId(category),
    endpoint_category: category,
    last_check_at: timestamp(NOW),
    current_status: failure === 'none' ? 'healthy' : (failure.startsWith('certificate_') || failure === 'response_slow' ? 'degraded' : 'down'),
    failure_category: failure,
    http_status: route ? (failure === 'http_5xx' ? 503 : 200) : null,
    redirect_count: failure === 'unexpected_redirect' ? 1 : 0,
    response_time_ms: route ? (failure === 'response_slow' ? 3100 : 120) : null,
    tls_status: category === 'tls' ? (failure === 'none' ? 'valid' : 'invalid') : 'not_applicable',
    certificate_expires_at: category === 'tls' ? '2026-12-31T00:00:00Z' : null,
    dns_status: category === 'dns' ? (failure === 'none' ? 'resolved' : 'failed') : 'not_applicable',
    content_status: route ? (failure === 'content_missing' ? 'missing' : 'present') : 'not_applicable',
    consecutive_failures: failure === 'none' ? 0 : 1,
    consecutive_successes: failure === 'none' ? 1 : 0,
    incident_id_hash: null,
    incident_started_at: null,
  };
}

function evidence(sequence = 1, previous = null) {
  const record = {
    schema_version: SCHEMA_VERSION,
    sequence,
    generated_at: '2026-07-29T00:00:00Z',
    fresh_until: '2026-07-29T01:20:00Z',
    producer: 'github-actions-external-uptime',
    observation_window: { started_at: '2026-07-29T00:00:00Z', ended_at: '2026-07-29T00:00:10Z' },
    current_status: 'healthy',
    last_success_at: '2026-07-29T00:00:00Z',
    last_incident: null,
    uptime_24h_basis_points: 10000,
    uptime_30d_basis_points: 10000,
    endpoint_results: ['dns', 'tls', 'route_no', 'route_en', 'route_ar'].map((category) => endpoint(category)),
    previous_evidence_fingerprint: previous?.evidence_fingerprint || null,
    evidence_fingerprint: '0'.repeat(64),
    authentication: {
      scheme: 'ed25519',
      key_id: 'econnet-uptime-ed25519-2026-01',
      signature_domain: SCHEMA_VERSION,
      signature: 'A'.repeat(86) + '==',
    },
  };
  return signEvidence(record, privateKeyPem);
}

test('1 all endpoints healthy', () => {
  assert.equal(classifyObservation(['dns', 'tls', 'route_no', 'route_en', 'route_ar'].map((item) => endpoint(item))), 'none');
});

test('2 DNS failure has highest priority', async () => {
  const result = await probeDns({ resolver: async () => { throw new Error('dns'); }, now: NOW });
  assert.equal(result.failure_category, 'dns_failure');
});

test('3 TLS failure is fail closed', async () => {
  const result = await probeTls({ connect: async () => { throw new Error('tls'); }, now: NOW });
  assert.equal(result.failure_category, 'tls_failure');
});

test('4 HTTP timeout is classified', async () => {
  const result = await probeRoute(ROUTES[0], { fetcher: async () => { throw new Error('total-timeout'); }, now: NOW });
  assert.equal(result.failure_category, 'timeout');
});

test('5 HTTP 5xx is classified', async () => {
  const result = await probeRoute(ROUTES[0], { fetcher: async (url) => ({ status: 503, redirects: 0, finalUrl: url, responseTimeMs: 10, body: '' }), now: NOW });
  assert.equal(result.failure_category, 'http_5xx');
});

test('6 unexpected redirect is rejected', async () => {
  const result = await probeRoute(ROUTES[0], { fetcher: async (url) => ({ status: 200, redirects: 1, finalUrl: url, responseTimeMs: 10, body: '' }), now: NOW });
  assert.equal(result.failure_category, 'unexpected_redirect');
});

for (const [number, route] of ROUTES.entries()) {
  test(`${7 + number} missing ${route.endpoint_category} marker`, async () => {
    const result = await probeRoute(route, { fetcher: async (url) => ({ status: 200, redirects: 0, finalUrl: url, responseTimeMs: 10, body: `<html lang="${route.lang}"></html>` }), now: NOW });
    assert.equal(result.failure_category, 'content_missing');
  });
}

test('10 one transient failure is not published', () => {
  const candidate = advanceCandidate(null, 'dns_failure');
  assert.equal(decidePublication('healthy', candidate).publish, false);
});

test('11 two failures confirm incident', () => {
  const first = advanceCandidate(null, 'dns_failure');
  const second = advanceCandidate(first, 'dns_failure');
  assert.deepEqual(decidePublication('healthy', second), {
    publish: true,
    transition: true,
    confirmedStatus: 'down',
    reason: 'transition:healthy->down',
  });
});

test('12 recovery requires two successes', () => {
  const first = advanceCandidate({ category: 'dns_failure', failures: 2, successes: 0, slow: 0 }, 'none');
  assert.equal(decidePublication('down', first).publish, false);
  assert.equal(decidePublication('down', advanceCandidate(first, 'none')).confirmedStatus, 'healthy');
});

test('13 three slow observations warn', () => {
  let candidate = null;
  for (let index = 0; index < 3; index += 1) candidate = advanceCandidate(candidate, 'response_slow');
  assert.equal(decidePublication('healthy', candidate).confirmedStatus, 'degraded');
});

test('14 certificate expiry 30 days', () => assert.equal(certificateFailure(30), 'certificate_expiring_30'));
test('15 certificate expiry 14 days', () => assert.equal(certificateFailure(14), 'certificate_expiring_14'));
test('16 certificate expiry 7 days', () => assert.equal(certificateFailure(7), 'certificate_expiring_7'));

test('17 sequence regression is rejected', () => {
  const previous = evidence(1);
  const next = evidence(1, previous);
  assert.throws(() => validateEvidence(next, { publicKeyPem, previousRecord: previous, now: NOW }), /sequence/);
});

test('18 previous fingerprint mismatch is rejected', () => {
  const previous = evidence(1);
  const next = evidence(2, { evidence_fingerprint: 'f'.repeat(64) });
  assert.throws(() => validateEvidence(next, { publicKeyPem, previousRecord: previous, now: NOW }), /previous_evidence/);
});

test('19 workflow concurrency prevents conflicting writes', async () => {
  const workflow = await readFile('.github/workflows/external-uptime.yml', 'utf8');
  assert.match(workflow, /concurrency:/);
  assert.match(workflow, /cancel-in-progress:\s*false/);
  assert.match(workflow, /evidence branch advanced unexpectedly/);
  assert.doesNotMatch(workflow, /push\s+--force|force-with-lease/);
});

test('20 Ed25519 verification succeeds', () => {
  assert.equal(validateEvidence(evidence(), { publicKeyPem, now: NOW }), true);
});

test('21 tampered evidence is rejected', () => {
  const record = evidence();
  record.current_status = 'down';
  assert.throws(() => validateEvidence(record, { publicKeyPem, now: NOW }), /fingerprint/);
});

test('22 unknown schema fields are rejected', () => {
  const record = evidence();
  record.raw_response = 'prohibited';
  assert.throws(() => validateEvidence(record, { publicKeyPem, now: NOW }), /unknown-or-missing/);
});

test('23 stale evidence is rejected', () => {
  assert.throws(() => validateEvidence(evidence(), { publicKeyPem, now: new Date('2026-07-29T02:00:00Z') }), /stale/);
});

test('24 dependent failures share one incident group', () => {
  assert.equal(groupIncident('timeout'), 'root');
  assert.equal(groupIncident('http_5xx'), 'root');
  assert.equal(incidentId('timeout', timestamp(NOW)), incidentId('http_5xx', timestamp(NOW)));
});

test('25 expired maintenance window is inactive', () => {
  const active = validateMaintenance({
    schema_version: 'econnet-uptime-maintenance/1.0.0',
    windows: [{ starts_at: '2026-07-28T00:00:00Z', ends_at: '2026-07-28T01:00:00Z', reason: 'planned test' }],
  }, NOW);
  assert.equal(active.length, 0);
});

test('retry occurs once after a failed observation', async () => {
  let calls = 0;
  let sleeps = 0;
  const routeProbe = async (route) => {
    calls += 1;
    return endpoint(route.endpoint_category, calls <= 3 ? 'content_missing' : 'none');
  };
  await probeAll({
    now: NOW,
    dnsProbe: async () => endpoint('dns'),
    tlsProbe: async () => endpoint('tls'),
    routeProbe,
    retryDelay: 60000,
    sleep: async (milliseconds) => { assert.equal(milliseconds, 60000); sleeps += 1; },
  });
  assert.equal(sleeps, 1);
  assert.equal(calls, 6);
});

test('canonical serialization is stable', () => {
  assert.equal(canonicalize({ b: 2, a: { z: 1, y: 0 } }), '{"a":{"y":0,"z":1},"b":2}');
  assert.equal(calculateEvidenceFingerprint(evidence()).length, 64);
});

test('publisher creates and verifies an initial signed checkpoint', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'econnet-uptime-'));
  const outputFile = join(stateRoot, 'result.json');
  const result = await produce({
    stateRoot,
    outputFile,
    privateKeyPem,
    publicKeyPem,
    observation: {
      started_at: '2026-07-29T00:00:00Z',
      ended_at: '2026-07-29T00:00:10Z',
      category: 'none',
      endpoint_results: ['dns', 'tls', 'route_no', 'route_en', 'route_ar'].map((category) => endpoint(category)),
    },
    now: NOW,
  });
  const record = JSON.parse(await readFile(join(stateRoot, 'evidence', 'current.json'), 'utf8'));
  assert.equal(result.publish, true);
  assert.equal(validateEvidence(record, { publicKeyPem, now: NOW }), true);
});
