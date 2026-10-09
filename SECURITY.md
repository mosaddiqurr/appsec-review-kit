# Security policy

This toolkit guides reviews; it does not guarantee application security, certify
compliance, or replace professional security testing. Instructions are not an OS
sandbox. Read [safety boundaries](docs/safety.md) before use.

## Reporting a toolkit vulnerability

For a weakness in the toolkit itself (for example, path escape, report injection,
or instructions that expose private data), use the repository's GitHub **Security →
Report a vulnerability** facility when enabled. Include a minimal synthetic
reproduction, affected toolkit revision, expected/observed behavior, and impact.
Do not submit live credentials, private application code, or target reports.

If private reporting is not available, open a public issue containing only a request
for a private contact route; withhold technical exploit details and sensitive data.
Maintainers must enable GitHub private vulnerability reporting before public
publication. No private contact address or response-time SLA is fabricated here.

Vulnerabilities in applications reviewed with this toolkit belong to their owners'
disclosure processes, not this project's public tracker. If credentials are exposed,
notify the authorized owner through their private channel and follow approved
revocation/rotation procedures; do not test the credentials or publish them.

## Supported releases

Version 1.0.x is the initial supported line. Maintenance is best effort; no guaranteed
response or remediation timeline is promised. Use a reviewed revision and consult
the changelog for corrections to guidance, report formats, or helper behavior.

## Evidence handling

Store target reports and raw tool outputs only in excluded private locations.
`.gitignore` prevents ordinary accidental staging; it is not access control, secure
deletion, or encryption. Redaction is best effort. Review evidence manually before
sharing and follow the application's data retention rules. Only clearly marked
synthetic reports belong in `examples/`.
