# Econnet external uptime evidence

This public repository contains only sanitized, independently produced uptime
evidence for the public Econnet website.

It contains no Econnet application source, Production configuration, private
paths, credentials, provider tokens, customer data, response bodies, response
headers, cookies, or resolved IP-address history.

The scheduled workflow checks the three public language routes, DNS resolution,
TLS validity, certificate expiry, redirect behavior, HTTP status, response
time, the document language, and one stable public content marker. It never
submits forms, signs in, or writes to Production.

UptimeRobot Free is the primary owner-alerting service. This repository is a
separate verification and signed-evidence channel. Monitoring detects outages;
it does not repair Production and does not replace Econnet Observer, backups,
a WAF, cPanel, or Disaster Recovery.

## Public endpoints

- `https://econnet.no/`
- `https://econnet.no/en/`
- `https://econnet.no/ar/`

## Evidence

Published records use the strict
`econnet-observer-external-uptime/1.0.0` schema. Records are canonically
serialized, fingerprinted with SHA-256, linked to the previous fingerprint,
and signed with the repository's Ed25519 key.

The signing private key exists only as the GitHub Actions secret
`UPTIME_ED25519_PRIVATE_KEY`. The public verification key is stored in
`keys/public-key.pem`.

The `evidence` branch is the append-only publication channel:

- `evidence/current.json` — latest signed record;
- `evidence/checkpoints/` — hourly and transition checkpoints;
- `evidence/incidents/` — sanitized incident lifecycle records.

Candidate observations between publications are recorded as sanitized GitHub
commit statuses on the latest `evidence` commit. This preserves the two-check
confirmation policy without committing every healthy ten-minute observation.

## Commands

```bash
npm test
npm run validate
npm run secret-scan
node scripts/verify.mjs evidence/current.json
```

See [the architecture](docs/architecture.md), [incident
runbook](docs/incident-runbook.md), and [UptimeRobot owner
guide](docs/uptimerobot-setup.md).
