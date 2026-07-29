# Security policy

## Public-data boundary

Only public endpoint categories and bounded uptime observations may be
published. The following are forbidden:

- private or resolved IP-address history;
- raw HTML, response bodies, or response headers;
- cookies, nonces, credentials, API tokens, or private keys;
- WordPress, cPanel, mail, database, or Observer configuration;
- customer, enquiry, mailbox, or account data;
- private filesystem paths.

Reports should describe a finding without attaching sensitive material.

## Signing

Evidence is signed using Ed25519 with domain
`econnet-observer-external-uptime/1.0.0`. The private key is a GitHub Actions
secret and must never be downloaded, printed, committed, or copied to
Production. Key rotation requires a reviewed change that adds a new public key
and stable key identifier before the old key is retired.

## Reporting

Report a suspected secret exposure or evidence-forgery issue privately to the
repository owner. Do not open a public issue containing secrets or private
operational data.
