# External uptime architecture

## Separation of responsibilities

1. **UptimeRobot Free** checks the public routes every five minutes and sends
   outage and recovery email to `sdcmmrc@gmail.com`.
2. **GitHub Actions** independently checks the same routes every ten minutes
   plus DNS and TLS posture.
3. **This repository** publishes only authenticated, sanitized evidence.
4. **Econnet Observer**, in a future separately reviewed sprint, may consume a
   verified local cache. The WordPress dashboard must never originate the
   monitoring request.

No component performs repair, restart, deployment, approval, rollback, or
configuration mutation.

## Monitoring levels

### Availability

- `econnet.no` resolves;
- TLS hostname and chain validation succeed;
- the final response is HTTP 200;
- redirects remain zero.

### Application health

- `/`, `/en/`, and `/ar/` respond;
- each document has the expected `lang` attribute;
- each route contains its stable public H1 marker.

### Service posture

- certificate expiry thresholds at 30, 14, and 7 days;
- response degradation above 3000 ms;
- cross-route failure grouping;
- DNS and TLS failures take precedence over dependent route failures.

## State and publication

The workflow uses one concurrency group with `cancel-in-progress: false`.
Each observation posts one sanitized commit status to the current `evidence`
branch commit. The status description contains only a bounded failure category
and confirmation counters.

A Git commit is created only for:

- a confirmed outage after two consecutive matching failures;
- a confirmed recovery after two consecutive successes;
- the third consecutive slow observation;
- a certificate threshold transition;
- one hourly signed checkpoint.

All pushes are non-force pushes. Before publishing, the producer refetches the
remote `evidence` tip and requires it to match the state it validated.

## Evidence authentication

The producer removes `evidence_fingerprint` and the signature value, retains
the public authentication metadata, canonically serializes that object, and
hashes it with SHA-256. It signs:

```text
econnet-observer-external-uptime/1.0.0
<lowercase evidence fingerprint>
```

with Ed25519. Verification requires:

- strict schema and unknown-field rejection;
- canonical fingerprint equality;
- valid Ed25519 signature and key identifier;
- monotonic sequence;
- previous-fingerprint linkage;
- non-expired `fresh_until`.

## Public evidence limitations

GitHub scheduled workflows can be delayed. GitHub runner geography is not an
availability guarantee. UptimeRobot remains the primary owner-alert path.
Observer will not display a new external observation while Production itself
is unavailable; the provider email and public repository remain available.

The public record is an operational signal, not an SLA, audit certificate,
backup, WAF, or recovery mechanism.

## Cost controls

- public repository;
- standard Ubuntu runner only;
- no artifacts or caches;
- no larger runners;
- no paid actions or monitoring features;
- no payment information;
- no provider API token;
- no automatic upgrade.

Before changing this repository to private visibility, scheduled monitoring
must be reviewed or disabled because private-repository Actions quotas and
billing differ.
