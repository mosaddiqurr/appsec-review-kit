# Validation evidence and limits

Release verification: 2026-10-10, Windows, Python 3.12.10 and 3.13.3.
All fixtures use synthetic data and pure local functions. No target application,
paid key, package installation, live service, or security scanner was used.

## Commands and observed results

Run from the toolkit root:

| Command | Actual local result |
| --- | --- |
| `python scripts/toolkit.py render-checks` | Regenerated the guide from the canonical 30-control registry |
| `python -m examples.build_examples` | 7 fixture tests passed; rebuilt 3 synthetic JSON/Markdown pairs |
| `python scripts/toolkit.py validate` | 30 controls, 3 reports, generated content, evidence line bounds, both prompt copies, and 78 local file/heading links validated |
| `python -m unittest discover -s tests -v` | 71 tests passed on Python 3.12.10; no failures, errors, or skips |
| `py -3.13 scripts/toolkit.py validate` | Same repository validation passed on Python 3.13.3 |
| `py -3.13 -m unittest discover -s tests -v` | 71 tests passed on Python 3.13.3; no failures, errors, or skips |
| `python scripts/toolkit.py tools` | Semgrep, Gitleaks, and OSV-Scanner MISSING / NOT RUN; availability lookup only |

Reporting CLI smoke checks also completed successfully:

```sh
python scripts/toolkit.py new --workspace . --project-name "Final release report check" --review-date 2026-10-10 --stem release-final
python scripts/toolkit.py report --workspace . --input .security-reports/release-final.json --stem release-final-report --html
python scripts/toolkit.py report --workspace . --input examples/reports/mixed-findings.json --stem release-final-example --html
```

The skeleton command wrote one JSON file. Each renderer command wrote redacted
JSON, Markdown, and escaped standalone HTML under ignored `.security-reports/`.
They assess no application and start no service. Existing outputs are preserved;
choose unused stems when repeating these commands. End-to-end tests additionally
verify source preservation, redaction, invalid-input rejection, and overwrite refusal.

## Controls, references, and publication content

Reviewed all 30 control definitions for stable/unique IDs, names, applicability,
detection guidance, safe remediation, verification, relevant official references,
and explicit automation limits. Preserved all IDs and names; normalized SEC-01's
OWASP URL to its canonical `.html` page and regenerated the guide. All 60 distinct
control-reference URLs returned HTTP 200 during the release check. These remote
checks are a release review step, not part of the offline validator.

README branding and the repository URL are AppSec Review Kit and
https://github.com/mosaddiqurr/appsec-review-kit throughout public project content.
Both complete README prompt blocks match `prompts/universal.md`: one follows
the introduction, and one remains the final section and content. Fenced text
blocks use GitHub's native copy control without HTML buttons or JavaScript. Coverage-table names match the canonical registry.

Local content review found only synthetic redaction-test strings and documentation
text among sensitive-pattern candidates; no actual credentials were identified.
Private reports, credential-file patterns, and Python caches are ignored. This is
bounded manual/pattern review, not a Gitleaks run or a guarantee that no secret exists.
Only the explicitly staged public tree should be published.

## Coverage and boundaries

Tests cover registry completeness, metadata, report schema/type/date validation,
duplicate JSON keys, nonstandard constants, applicability/status consistency,
evidence and fix references, failing-before/passing-after requirements, deterministic
examples, redaction, output escaping, missing tools, workspace paths, exclusive
outputs, symlink escapes, source preservation, and CLI reporting.

Documentation checks cover inline local file links and GitHub-style ATX heading
anchors used by this repository, including duplicate headings and fenced examples.
They also reject drift in either prompt copy, require both copy sections in the
correct positions, preserve unrelated code blocks, and check all 30 control names.
The link checker is scoped to this project's Markdown conventions, not a general
Markdown parser or remote-link monitor.

Both Windows runs executed the symlink test successfully. POSIX private-mode
assertions were not exercised locally; Windows privacy uses inherited ACLs. All
Python sources also parsed with Python 3.10 grammar, a syntax check that does not
establish runtime compatibility on 3.10.

These checks verify toolkit behavior and synthetic examples. They do not automate
all 30 security assessments, authenticate evidence in user reports, or prove an
application secure. Business rules, deployment, identity-provider configuration,
and recovery still require appropriate evidence and owner review.

## Hosted and optional checks

The GitHub Actions workflow was reviewed for syntax, push/pull-request triggers,
read-only contents permissions, immutable official action pins, disabled checkout
credential persistence, and absence of secrets/publication jobs. Pins were checked
against official release histories. The configured matrix runs Windows and Linux
with Python 3.10, 3.12, and 3.14. Hosted outcomes must be checked for the published
commit and are recorded in the publication handoff; local results do not establish
hosted CI success. POSIX permission tests execute on Linux.

Documented scanner flags were checked against official documentation, including
Semgrep privacy options, Gitleaks v8 directory/history modes, and OSV-Scanner v2
source scanning/output flags. None of these scanners was installed or executed.
Cross-provider audit accuracy and every framework remain unvalidated.
