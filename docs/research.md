# Reference review and positioning

Official sources reviewed on 2026-10-09. Content below is original guidance with
links, not copied standard text. These review areas are not an exhaustive standard
mapping, certification, or claim of OWASP/MITRE endorsement.

| Reference | Observed role | Use here |
| --- | --- | --- |
| [OWASP ASVS](https://github.com/OWASP/ASVS) | Published application verification requirements; repository identifies stable 5.0.0 and distinguishes development content | Background for verification discipline; no unverified requirement-number mappings |
| [OWASP Top 10:2025](https://top10.owasp.org/2025/) | Broad risk awareness | Context, not an exhaustive test checklist |
| [OWASP API Security Top 10](https://owasp.org/API-Security/) | 2023 API risk guidance, including object/function authorization and resource consumption | API-specific review context |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | Focused defensive implementation guidance | Linked per control for deeper remediation review |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness taxonomy | Relevant weakness links; not a declaration that every control failure is precisely that CWE |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) | Deeper web security test procedures | Escalation resource beyond this compact workflow |
| [OAuth security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Current OAuth security considerations | Protocol-specific guidance for SEC-22 |
| [PostgreSQL row policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) | Effective row security, role bypass, and policy behavior | Concrete vendor considerations for SEC-14; other vendors differ |
| [Semgrep CLI](https://semgrep.dev/docs/cli-reference), [Gitleaks](https://github.com/gitleaks/gitleaks), [OSV-Scanner usage](https://google.github.io/osv-scanner/usage/) | Established static analysis, secret detection, and advisory scanning | Optional documented local commands; no fabricated runs |

## Comparison with established playbooks

ASVS is substantially broader and better suited to specifying verification
requirements; WSTG provides deeper testing procedures. The Cheat Sheet Series is
a reference collection for implementation choices. This toolkit adds a compact
agent entry prompt, explicit applicability/evidence states, private structured
reporting, and a bounded remediation handoff. It complements those projects;
it does not replace their coverage or provide an assessment certification.

## Implementation decisions

Use code for exact IDs, required metadata, schema validation, cross-reference/status
consistency, escaping/redaction, and deterministic rendering. Use agent reasoning
for stack/trust boundaries, data flow, candidate triage, severity context, and minimal
fixes. Require owner/operator evidence for business rules, deployed policies, keys,
capacity, recovery, and consequential actions. See [architecture](architecture.md).

No scanners were installed during development. The local availability check found
Semgrep, Gitleaks, and OSV-Scanner missing. Documented commands were checked against
official documentation, not executed scanner results. CI action commit pins were
verified against the official [checkout release history](https://github.com/actions/checkout/releases)
and [setup-python release history](https://github.com/actions/setup-python/releases).

Maintain references by checking official publications, recording review dates,
and updating guidance/tests together. Do not invent ASVS IDs or silently relabel
an old mapping with a new standard version. Specific CWE links describe relevant
failure types, not every aspect of a broad control (for example, backup disclosure
does not cover every recovery failure).
