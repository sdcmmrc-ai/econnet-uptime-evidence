import dns from 'node:dns/promises';
import https from 'node:https';
import tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { certificateFailure, classifyObservation, monitorId, timestamp } from './lib.mjs';

export const ROUTES = [
  {
    endpoint_category: 'route_no',
    url: 'https://econnet.no/',
    lang: 'nb-NO',
    marker: 'Én partner for hele den digitale reisen.',
  },
  {
    endpoint_category: 'route_en',
    url: 'https://econnet.no/en/',
    lang: 'en',
    marker: 'One partner for your entire digital journey.',
  },
  {
    endpoint_category: 'route_ar',
    url: 'https://econnet.no/ar/',
    lang: 'ar',
    marker: 'شريك واحد لرحلتك الرقمية بأكملها.',
  },
];

const BODY_LIMIT = 512 * 1024;

function emptyResult(category, checkedAt) {
  return {
    monitor_id_hash: monitorId(category),
    endpoint_category: category,
    last_check_at: checkedAt,
    current_status: 'unknown',
    failure_category: 'none',
    http_status: null,
    redirect_count: 0,
    response_time_ms: null,
    tls_status: category === 'tls' ? 'unknown' : 'not_applicable',
    certificate_expires_at: null,
    dns_status: category === 'dns' ? 'unknown' : 'not_applicable',
    content_status: category.startsWith('route_') ? 'unknown' : 'not_applicable',
    consecutive_failures: 0,
    consecutive_successes: 0,
    incident_id_hash: null,
    incident_started_at: null,
  };
}

export async function probeDns({ resolver = dns.resolveAny, now = new Date() } = {}) {
  const result = emptyResult('dns', timestamp(now));
  try {
    const answers = await resolver('econnet.no');
    if (!Array.isArray(answers) || answers.length === 0) throw new Error('empty');
    result.current_status = 'healthy';
    result.dns_status = 'resolved';
  } catch {
    result.current_status = 'down';
    result.failure_category = 'dns_failure';
    result.dns_status = 'failed';
  }
  return result;
}

function defaultTlsConnect(options) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(options);
    const connectTimer = setTimeout(() => socket.destroy(new Error('connect-timeout')), 5000);
    const totalTimer = setTimeout(() => socket.destroy(new Error('total-timeout')), 15000);
    socket.once('secureConnect', () => {
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      const certificate = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError;
      socket.end();
      resolve({ certificate, authorized, authorizationError });
    });
    socket.once('error', (error) => {
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      reject(error);
    });
  });
}

export async function probeTls({ connect = defaultTlsConnect, now = new Date() } = {}) {
  const result = emptyResult('tls', timestamp(now));
  try {
    const { certificate, authorized } = await connect({
      host: 'econnet.no',
      servername: 'econnet.no',
      port: 443,
      rejectUnauthorized: true,
    });
    if (!authorized || !certificate?.valid_to) throw new Error('invalid');
    const expires = new Date(certificate.valid_to);
    if (Number.isNaN(expires.getTime())) throw new Error('invalid-expiry');
    const days = (expires.getTime() - now.getTime()) / 86400000;
    const expiryFailure = certificateFailure(days);
    result.certificate_expires_at = timestamp(expires);
    result.tls_status = expiryFailure === 'none' ? 'valid' : 'expiring';
    result.failure_category = expiryFailure;
    result.current_status = expiryFailure === 'none' ? 'healthy' : 'degraded';
  } catch {
    result.current_status = 'down';
    result.failure_category = 'tls_failure';
    result.tls_status = 'invalid';
  }
  return result;
}

function requestOnce(url, { request = https.request } = {}) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const controller = new AbortController();
    const totalTimer = setTimeout(() => controller.abort(), 15000);
    let connectTimer;
    const req = request(url, {
      method: 'GET',
      headers: {
        Accept: 'text/html,application/xhtml+xml',
        'Accept-Encoding': 'identity',
        'User-Agent': 'EconnetExternalUptime/1.0 (+https://github.com/sdcmmrc-ai/econnet-uptime-evidence)',
      },
      signal: controller.signal,
    }, (response) => {
      clearTimeout(connectTimer);
      let bytes = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > BODY_LIMIT) {
          req.destroy(new Error('body-limit'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        clearTimeout(totalTimer);
        resolve({
          status: response.statusCode,
          location: response.headers.location || null,
          body: Buffer.concat(chunks).toString('utf8'),
          responseTimeMs: Math.round(performance.now() - started),
        });
      });
    });
    req.on('socket', (socket) => {
      if (socket.connecting) {
        connectTimer = setTimeout(() => req.destroy(new Error('connect-timeout')), 5000);
        socket.once('connect', () => clearTimeout(connectTimer));
      }
    });
    req.once('error', (error) => {
      clearTimeout(connectTimer);
      clearTimeout(totalTimer);
      reject(error);
    });
    req.end();
  });
}

async function fetchFollowingRedirects(startUrl, dependencies) {
  let current = new URL(startUrl);
  let redirects = 0;
  while (true) {
    const response = await requestOnce(current, dependencies);
    if (![301, 302, 303, 307, 308].includes(response.status) || !response.location) {
      return { ...response, redirects, finalUrl: current.href };
    }
    if (redirects >= 3) throw new Error('redirect-limit');
    current = new URL(response.location, current);
    redirects += 1;
  }
}

export async function probeRoute(route, { fetcher = fetchFollowingRedirects, now = new Date() } = {}) {
  const result = emptyResult(route.endpoint_category, timestamp(now));
  try {
    const response = await fetcher(route.url);
    result.http_status = response.status;
    result.redirect_count = response.redirects;
    result.response_time_ms = response.responseTimeMs;
    const final = new URL(response.finalUrl);
    const expected = new URL(route.url);
    if (response.redirects > 0 || final.origin !== expected.origin || final.pathname !== expected.pathname) {
      result.current_status = 'down';
      result.failure_category = 'unexpected_redirect';
      return result;
    }
    if (response.status >= 500) {
      result.current_status = 'down';
      result.failure_category = 'http_5xx';
      return result;
    }
    if (response.status !== 200) {
      result.current_status = 'down';
      result.failure_category = route.endpoint_category === 'route_no' ? 'root_route_failure' : 'language_route_failure';
      return result;
    }
    const languagePattern = new RegExp(`<html\\b[^>]*\\blang=["']${route.lang.replace('-', '\\-')}["']`, 'i');
    if (!languagePattern.test(response.body) || !response.body.includes(route.marker)) {
      result.current_status = 'down';
      result.failure_category = 'content_missing';
      result.content_status = 'missing';
      return result;
    }
    result.content_status = 'present';
    if (response.responseTimeMs > 3000) {
      result.current_status = 'degraded';
      result.failure_category = 'response_slow';
    } else {
      result.current_status = 'healthy';
    }
  } catch (error) {
    result.current_status = 'down';
    result.failure_category = String(error?.message || '').includes('timeout') || error?.name === 'AbortError'
      ? 'timeout'
      : (route.endpoint_category === 'route_no' ? 'root_route_failure' : 'language_route_failure');
  }
  return result;
}

export async function probeAll({
  now = new Date(),
  dnsProbe = probeDns,
  tlsProbe = probeTls,
  routeProbe = probeRoute,
  retryDelay = 60000,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
} = {}) {
  const startedAt = timestamp(now);
  const observe = async () => {
    const dnsResult = await dnsProbe({ now });
    const tlsResult = await tlsProbe({ now });
    const routeResults = [];
    for (const route of ROUTES) routeResults.push(await routeProbe(route, { now }));
    return [dnsResult, tlsResult, ...routeResults];
  };
  let results = await observe();
  let category = classifyObservation(results);
  if (category !== 'none') {
    await sleep(retryDelay);
    results = await observe();
    category = classifyObservation(results);
  }
  return {
    started_at: startedAt,
    ended_at: timestamp(new Date()),
    category,
    endpoint_results: results,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await probeAll();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.category === 'none' ? 0 : 1;
}
