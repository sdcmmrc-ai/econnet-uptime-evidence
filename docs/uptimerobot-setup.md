# UptimeRobot Free owner setup

This guide is intentionally explicit. Do not select a trial or enter payment
information.

## Account

1. Open <https://uptimerobot.com/signUp>.
2. Create or confirm the Free account using `sdcmmrc@gmail.com`.
3. Confirm that the selected plan says **Free**, **$0**, **5-minute
   monitoring**, and **no credit card required**.
4. Do not start a paid trial and do not add SMS or voice credits.

## Alert contact

Use `sdcmmrc@gmail.com` for both down and recovery notifications. Do not use
`contact@econnet.no` as the only alert channel because the Econnet domain or
mail service may be affected by the same incident.

## Create exactly three monitors

Use a Keyword monitor when the Free interface offers it; otherwise use the
Free HTTPS monitor with the same URL and expected status.

| Name | URL | Expected status | Keyword |
|---|---|---:|---|
| Econnet — Norwegian | `https://econnet.no/` | 200 | `Én partner for hele den digitale reisen.` |
| Econnet — English | `https://econnet.no/en/` | 200 | `One partner for your entire digital journey.` |
| Econnet — Arabic | `https://econnet.no/ar/` | 200 | `شريك واحد لرحلتك الرقمية بأكملها.` |

For each monitor:

1. select HTTPS/Keyword monitoring;
2. set the interval to five minutes;
3. require HTTP 200 and no unexpected redirect where the UI supports it;
4. require that the keyword is present;
5. attach `sdcmmrc@gmail.com`;
6. enable both down and recovery email;
7. leave recurring/prolonging paid alerts, SMS, voice, paid integrations,
   paid retention, and paid status pages disabled.

The closest Free-plan policy is provider-confirmed failure followed by one down
email and one recovery email. Do not enable noisy repeating notifications.

## Optional DNS and SSL

Enable dedicated DNS or SSL-expiry monitoring only if the current Free
interface explicitly labels the feature `$0` and does not request a trial,
upgrade, or payment method. Otherwise leave it disabled; the GitHub verifier
covers both signals.

## Incident handling

- Acknowledge an active incident in the UptimeRobot incident view to show that
  it is being handled.
- Do not pause unrelated monitors.
- Wait for the recovery notification and verify the three public routes.
- Monitoring never authorizes an automatic Production repair.

## Maintenance

If Free supports maintenance windows, create a bounded window with an owner,
reason, UTC start, and UTC end. Never create an indefinite pause. If the
feature is paid, do not enable it; instead temporarily pause only the affected
monitor and document the start and required re-enable time.

## Verification

After saving:

1. all three monitors must show Up after their first checks;
2. the URLs and keywords must match this table exactly;
3. `sdcmmrc@gmail.com` must be the active down and recovery recipient;
4. no payment method, trial, SMS, voice, or paid feature may be present.

Do not create a synthetic outage against Econnet. Alert delivery can be tested
later with a separate harmless test monitor that is not a Production URL and
only after explicit owner authorization.
