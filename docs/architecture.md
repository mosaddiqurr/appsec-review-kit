# Design and maintenance

AppSec Review Kit 1.0.0 is a repository of instructions with optional local Python
utilities. There is no API, database, hosted service, agent framework, or paid-key
requirement. Existing coding agents supply file access and reasoning; the user's
chosen environment supplies permission enforcement.

| Responsibility | Implementation | Why |
| --- | --- | --- |
| Review scope, stack, data flow, applicability | Prompts and workflow | Requires context rather than generic pattern matching |
| 30 control definitions | `checks/controls.json` | One canonical registry with explicit metadata |
| Human-readable control guide | Generated `checks/README.md` | Usable without Python; staleness checked in validation |
| Report format and consistency | JSON Schema plus `scripts/toolkit.py` | Deterministic structure without dependencies |
| Redacted Markdown/JSON and optional HTML | Local renderer | Portable outputs, no web application |
| Scanner availability | PATH lookup | Reports missing tools without running untrusted binaries |
| Vulnerability detection | Reviewed established tools and agent/manual review | Avoids a misleading home-grown scanner |
| Regression examples | Pure local Python fixtures and unittest | Reproducible evidence without remote targets |
| Publication checks | Offline validation and GitHub Actions | No keys, scans, installations, or publication authority |

Only `render-checks` updates public generated guidance. Example report pairs are
deliberately checked in because they contain synthetic data; regenerate Markdown
with the renderer when their structured evidence changes. Tests check fixture
behavior and examples together. Actual target reports stay private.

Supported helper runtime: Python 3.10+. No pip dependencies. Development was tested
locally on Windows/Python 3.12.10 and 3.13.3; CI is configured for Windows/Linux on 3.10, 3.12,
and 3.14. A configured CI matrix is not a claim that hosted CI has already run.
Prompts are provider-independent text and can be used in Codex, Claude Code, or
another agent able to retrieve files and honor the workflow. Cross-provider audit
accuracy and every language/framework combination have not been validated.

The validator checks schema fields and consistency, not evidence truth, adequacy,
business policy, or exploitability. The redactor is a secondary output safeguard,
not a general secret scanner. See [safety boundaries](safety.md) and
[reporting](reporting.md) for filesystem and privacy limits.
