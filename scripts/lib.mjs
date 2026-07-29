import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

export const SCHEMA_VERSION = 'econnet-observer-external-uptime/1.0.0';
export const PRODUCER = 'github-actions-external-uptime';
export const KEY_ID = 'econnet-uptime-ed25519-2026-01';
export const ENDPOINT_CATEGORIES = ['dns', 'tls', 'route_no', 'route_en', 'route_ar'];
export const FAILURE_CATEGORIES = [
  'none',
  'dns_failure',
  'tls_failure',
  'root_route_failure',
  'language_route_failure',
  'content_missing',
  'response_slow',
  'http_5xx',
  'timeout',
  'unexpected_redirect',
  'certificate_expiring_30',
  'certificate_expiring_14',
  'certificate_expiring_7',
];

const TOP_LEVEL_KEYS = [
  'schema_version',
  'sequence',
  'generated_at',
  'fresh_until',
  'producer',
  'observation_window',
  'current_status',
  'last_success_at',
  'last_incident',
  'uptime_24h_basis_points',
  'uptime_30d_basis_points',
  'endpoint_results',
  'previous_evidence_fingerprint',
  'evidence_fingerprint',
  'authentication',
];

const ENDPOINT_KEYS = [
  'monitor_id_hash',
  'endpoint_category',
  'last_check_at',
  'current_status',
  'failure_category',
  'http_status',
  'redirect_count',
  'response_time_ms',
  'tls_status',
  'certificate_expires_at',
  'dns_status',
  'content_status',
  'consecutive_failures',
  'consecutive_successes',
  'incident_id_hash',
  'incident_started_at',
];

const ISO_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SHA256 = /^[a-f0-9]{64}$/;

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function timestamp(value = new Date()) {
  return new Date(value).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function monitorId(endpointCategory) {
  return sha256(`econnet-public-monitor/1\n${endpointCategory}`);
}

function unsignedEvidence(record) {
  const copy = structuredClone(record);
  delete copy.evidence_fingerprint;
  if (copy.authentication) {
    delete copy.authentication.signature;
  }
  return copy;
}

export function calculateEvidenceFingerprint(record) {
  return sha256(`${SCHEMA_VERSION}\n${canonicalize(unsignedEvidence(record))}`);
}

export function signEvidence(record, privateKeyPem) {
  const output = structuredClone(record);
  output.authentication = {
    scheme: 'ed25519',
    key_id: KEY_ID,
    signature_domain: SCHEMA_VERSION,
  };
  output.evidence_fingerprint = calculateEvidenceFingerprint(output);
  output.authentication.signature = sign(
    null,
    Buffer.from(`${SCHEMA_VERSION}\n${output.evidence_fingerprint}`, 'utf8'),
    createPrivateKey(privateKeyPem),
  ).toString('base64');
  return output;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label}:type`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label}:unknown-or-missing-fields`);
  }
}

function assertTimestamp(value, label) {
  if (typeof value !== 'string' || !ISO_SECONDS.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label}:timestamp`);
  }
}

function nullableTimestamp(value, label) {
  if (value !== null) {
    assertTimestamp(value, label);
  }
}

function nullableSha(value, label) {
  if (value !== null && (typeof value !== 'string' || !SHA256.test(value))) {
    throw new Error(`${label}:sha256`);
  }
}

function integerRange(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label}:integer-range`);
  }
}

export function validateEvidence(record, {
  publicKeyPem,
  previousRecord = null,
  now = new Date(),
  requireFresh = true,
} = {}) {
  exactKeys(record, TOP_LEVEL_KEYS, 'evidence');
  if (record.schema_version !== SCHEMA_VERSION || record.producer !== PRODUCER) {
    throw new Error('evidence:schema-or-producer');
  }
  integerRange(record.sequence, 1, Number.MAX_SAFE_INTEGER, 'sequence');
  assertTimestamp(record.generated_at, 'generated_at');
  assertTimestamp(record.fresh_until, 'fresh_until');
  if (Date.parse(record.fresh_until) <= Date.parse(record.generated_at)) {
    throw new Error('freshness:invalid-window');
  }
  if (requireFresh && Date.parse(record.fresh_until) <= now.getTime()) {
    throw new Error('freshness:stale');
  }
  exactKeys(record.observation_window, ['started_at', 'ended_at'], 'observation_window');
  assertTimestamp(record.observation_window.started_at, 'observation_window.started_at');
  assertTimestamp(record.observation_window.ended_at, 'observation_window.ended_at');
  if (Date.parse(record.observation_window.ended_at) < Date.parse(record.observation_window.started_at)) {
    throw new Error('observation_window:order');
  }
  if (!['healthy', 'degraded', 'down', 'unknown'].includes(record.current_status)) {
    throw new Error('current_status:enum');
  }
  nullableTimestamp(record.last_success_at, 'last_success_at');
  integerRange(record.uptime_24h_basis_points, 0, 10000, 'uptime_24h_basis_points');
  integerRange(record.uptime_30d_basis_points, 0, 10000, 'uptime_30d_basis_points');
  nullableSha(record.previous_evidence_fingerprint, 'previous_evidence_fingerprint');
  if (typeof record.evidence_fingerprint !== 'string' || !SHA256.test(record.evidence_fingerprint)) {
    throw new Error('evidence_fingerprint:sha256');
  }
  if (record.last_incident !== null) {
    exactKeys(record.last_incident, ['incident_id_hash', 'failure_category', 'started_at', 'recovered_at'], 'last_incident');
    nullableSha(record.last_incident.incident_id_hash, 'last_incident.incident_id_hash');
    if (!FAILURE_CATEGORIES.includes(record.last_incident.failure_category) || record.last_incident.failure_category === 'none') {
      throw new Error('last_incident.failure_category:enum');
    }
    assertTimestamp(record.last_incident.started_at, 'last_incident.started_at');
    nullableTimestamp(record.last_incident.recovered_at, 'last_incident.recovered_at');
  }
  if (!Array.isArray(record.endpoint_results) || record.endpoint_results.length !== ENDPOINT_CATEGORIES.length) {
    throw new Error('endpoint_results:cardinality');
  }
  const seen = new Set();
  for (const endpoint of record.endpoint_results) {
    exactKeys(endpoint, ENDPOINT_KEYS, 'endpoint');
    if (!ENDPOINT_CATEGORIES.includes(endpoint.endpoint_category) || seen.has(endpoint.endpoint_category)) {
      throw new Error('endpoint:endpoint_category');
    }
    seen.add(endpoint.endpoint_category);
    if (endpoint.monitor_id_hash !== monitorId(endpoint.endpoint_category)) {
      throw new Error('endpoint:monitor_id_hash');
    }
    assertTimestamp(endpoint.last_check_at, 'endpoint.last_check_at');
    if (!['healthy', 'degraded', 'down', 'unknown'].includes(endpoint.current_status)) {
      throw new Error('endpoint.current_status:enum');
    }
    if (!FAILURE_CATEGORIES.includes(endpoint.failure_category)) {
      throw new Error('endpoint.failure_category:enum');
    }
    if (endpoint.http_status !== null) integerRange(endpoint.http_status, 100, 599, 'endpoint.http_status');
    integerRange(endpoint.redirect_count, 0, 3, 'endpoint.redirect_count');
    if (endpoint.response_time_ms !== null) integerRange(endpoint.response_time_ms, 0, 60000, 'endpoint.response_time_ms');
    if (!['valid', 'invalid', 'expiring', 'not_applicable', 'unknown'].includes(endpoint.tls_status)) {
      throw new Error('endpoint.tls_status:enum');
    }
    nullableTimestamp(endpoint.certificate_expires_at, 'endpoint.certificate_expires_at');
    if (!['resolved', 'failed', 'not_applicable', 'unknown'].includes(endpoint.dns_status)) {
      throw new Error('endpoint.dns_status:enum');
    }
    if (!['present', 'missing', 'not_applicable', 'unknown'].includes(endpoint.content_status)) {
      throw new Error('endpoint.content_status:enum');
    }
    integerRange(endpoint.consecutive_failures, 0, 1000, 'endpoint.consecutive_failures');
    integerRange(endpoint.consecutive_successes, 0, 1000, 'endpoint.consecutive_successes');
    nullableSha(endpoint.incident_id_hash, 'endpoint.incident_id_hash');
    nullableTimestamp(endpoint.incident_started_at, 'endpoint.incident_started_at');
  }
  exactKeys(record.authentication, ['scheme', 'key_id', 'signature_domain', 'signature'], 'authentication');
  if (
    record.authentication.scheme !== 'ed25519'
    || record.authentication.key_id !== KEY_ID
    || record.authentication.signature_domain !== SCHEMA_VERSION
    || typeof record.authentication.signature !== 'string'
    || !/^[A-Za-z0-9+/]{86}==$/.test(record.authentication.signature)
  ) {
    throw new Error('authentication:metadata');
  }
  if (record.evidence_fingerprint !== calculateEvidenceFingerprint(record)) {
    throw new Error('evidence_fingerprint:mismatch');
  }
  if (publicKeyPem && !verify(
    null,
    Buffer.from(`${SCHEMA_VERSION}\n${record.evidence_fingerprint}`, 'utf8'),
    createPublicKey(publicKeyPem),
    Buffer.from(record.authentication.signature, 'base64'),
  )) {
    throw new Error('authentication:invalid-signature');
  }
  if (previousRecord) {
    if (record.sequence !== previousRecord.sequence + 1) {
      throw new Error('sequence:regression-or-gap');
    }
    if (record.previous_evidence_fingerprint !== previousRecord.evidence_fingerprint) {
      throw new Error('previous_evidence_fingerprint:mismatch');
    }
  } else if (record.sequence === 1 && record.previous_evidence_fingerprint !== null) {
    throw new Error('previous_evidence_fingerprint:first-record');
  }
  return true;
}

export function certificateFailure(daysRemaining) {
  if (!Number.isFinite(daysRemaining)) return 'tls_failure';
  if (daysRemaining <= 7) return 'certificate_expiring_7';
  if (daysRemaining <= 14) return 'certificate_expiring_14';
  if (daysRemaining <= 30) return 'certificate_expiring_30';
  return 'none';
}

export function classifyObservation(results) {
  const byCategory = Object.fromEntries(results.map((result) => [result.endpoint_category, result]));
  const dns = byCategory.dns;
  const tls = byCategory.tls;
  const root = byCategory.route_no;
  if (!dns || dns.failure_category !== 'none') return dns?.failure_category || 'dns_failure';
  if (!tls || tls.failure_category !== 'none') return tls?.failure_category || 'tls_failure';
  if (!root || ['timeout', 'http_5xx', 'unexpected_redirect', 'root_route_failure'].includes(root.failure_category)) {
    return root?.failure_category === 'none' ? 'root_route_failure' : (root?.failure_category || 'root_route_failure');
  }
  for (const category of ['route_en', 'route_ar']) {
    const route = byCategory[category];
    if (!route || ['timeout', 'http_5xx', 'unexpected_redirect', 'language_route_failure'].includes(route.failure_category)) {
      return route?.failure_category === 'none' ? 'language_route_failure' : (route?.failure_category || 'language_route_failure');
    }
  }
  const missing = results.find((result) => result.failure_category === 'content_missing');
  if (missing) return 'content_missing';
  const expiry = ['certificate_expiring_7', 'certificate_expiring_14', 'certificate_expiring_30']
    .find((category) => tls.failure_category === category);
  if (expiry) return expiry;
  if (results.some((result) => result.failure_category === 'response_slow')) return 'response_slow';
  return 'none';
}

export function encodeObservationStatus({ category, failures, successes, slow }) {
  return `obs:${category}:f${failures}:s${successes}:l${slow}`;
}

export function decodeObservationStatus(description) {
  const match = /^obs:([a-z0-9_]+):f(\d+):s(\d+):l(\d+)$/.exec(description || '');
  if (!match || !FAILURE_CATEGORIES.includes(match[1])) return null;
  return {
    category: match[1],
    failures: Number(match[2]),
    successes: Number(match[3]),
    slow: Number(match[4]),
  };
}

export function advanceCandidate(previous, category) {
  const prior = previous || { category: 'none', failures: 0, successes: 0, slow: 0 };
  if (category === 'none') {
    return { category, failures: 0, successes: prior.category === 'none' ? prior.successes + 1 : 1, slow: 0 };
  }
  if (category === 'response_slow') {
    return { category, failures: 0, successes: 0, slow: prior.category === category ? prior.slow + 1 : 1 };
  }
  return { category, failures: prior.category === category ? prior.failures + 1 : 1, successes: 0, slow: 0 };
}

export function decidePublication(previousStatus, candidate, { hourlyDue = false } = {}) {
  const certificateTransition = candidate.category.startsWith('certificate_expiring_');
  let confirmedStatus = previousStatus;
  let transition = false;
  if (candidate.category === 'none' && candidate.successes >= 2) {
    confirmedStatus = 'healthy';
    transition = previousStatus !== 'healthy';
  } else if (candidate.category === 'response_slow' && candidate.slow >= 3) {
    confirmedStatus = 'degraded';
    transition = previousStatus !== 'degraded';
  } else if (certificateTransition) {
    confirmedStatus = 'degraded';
    transition = previousStatus !== 'degraded';
  } else if (candidate.category !== 'none' && candidate.failures >= 2) {
    confirmedStatus = 'down';
    transition = previousStatus !== 'down';
  }
  return {
    publish: transition || hourlyDue,
    transition,
    confirmedStatus,
    reason: transition ? `transition:${previousStatus}->${confirmedStatus}` : (hourlyDue ? 'hourly-checkpoint' : 'candidate-only'),
  };
}

export function groupIncident(category) {
  if (category === 'dns_failure') return 'dns';
  if (category === 'tls_failure' || category.startsWith('certificate_expiring_')) return 'tls';
  if (['root_route_failure', 'http_5xx', 'timeout', 'unexpected_redirect'].includes(category)) return 'root';
  if (category === 'language_route_failure' || category === 'content_missing') return 'language';
  if (category === 'response_slow') return 'performance';
  return 'none';
}

export function validateMaintenance(config, now = new Date()) {
  exactKeys(config, ['schema_version', 'windows'], 'maintenance');
  if (config.schema_version !== 'econnet-uptime-maintenance/1.0.0' || !Array.isArray(config.windows)) {
    throw new Error('maintenance:schema');
  }
  return config.windows.filter((window) => {
    exactKeys(window, ['starts_at', 'ends_at', 'reason'], 'maintenance.window');
    assertTimestamp(window.starts_at, 'maintenance.window.starts_at');
    assertTimestamp(window.ends_at, 'maintenance.window.ends_at');
    if (typeof window.reason !== 'string' || window.reason.length < 1 || window.reason.length > 120) {
      throw new Error('maintenance.window.reason');
    }
    return Date.parse(window.starts_at) <= now.getTime() && now.getTime() < Date.parse(window.ends_at);
  });
}

export function uptimeBasisPoints(incidents, windowStart, windowEnd) {
  const start = new Date(windowStart).getTime();
  const end = new Date(windowEnd).getTime();
  if (!(end > start)) throw new Error('uptime:window');
  let downtime = 0;
  for (const incident of incidents) {
    const incidentStart = Math.max(start, Date.parse(incident.started_at));
    const incidentEnd = Math.min(end, incident.recovered_at ? Date.parse(incident.recovered_at) : end);
    if (incidentEnd > incidentStart) downtime += incidentEnd - incidentStart;
  }
  return Math.max(0, Math.min(10000, Math.round(((end - start - downtime) / (end - start)) * 10000)));
}

export function incidentId(category, startedAt) {
  return sha256(`${SCHEMA_VERSION}\nincident\n${groupIncident(category)}\n${startedAt}`);
}
