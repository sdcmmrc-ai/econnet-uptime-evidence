# External uptime incident runbook

## Alert categories

Priority is:

1. DNS failure;
2. TLS failure;
3. Norwegian root route failure;
4. English or Arabic route failure;
5. expected content missing;
6. repeated response degradation.

DNS, TLS, and root failures group dependent route symptoms into one incident.

## Confirmation

- Hard outages require two consecutive failed ten-minute GitHub observations.
- Recovery requires two consecutive successful observations.
- Slow response requires three consecutive observations over 3000 ms.
- Certificate thresholds transition at 30, 14, and 7 days.
- UptimeRobot uses its own distributed failure confirmation and supplies the
  primary down and recovery email.

## Owner response

1. Acknowledge the provider incident.
2. Check the public evidence repository and provider service status.
3. Determine whether DNS, TLS, hosting, or one language route is affected.
4. Contact the authorized provider or begin a separately authorized Production
   diagnostic.
5. Do not alter DNS, TLS, WordPress, or hosting merely to silence monitoring.
6. Confirm recovery from both public channels.

## Provider or evidence failure

If UptimeRobot is unavailable, GitHub verification continues. If GitHub Actions
is delayed, UptimeRobot remains authoritative for owner alerting. If evidence
is stale while the site is reachable, classify the evidence pipeline as
unavailable; do not classify the website as down.

## Planned maintenance

Maintenance must be bounded and recorded in `maintenance.json`. Expired
windows never suppress or alter a result. The foundation records and validates
windows but does not suppress monitoring or publication automatically; an
owner must interpret a coincident alert as planned maintenance.
