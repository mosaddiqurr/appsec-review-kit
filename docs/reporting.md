# Report contract (schema version 1)

[report.schema.json](../templates/report.schema.json) is the machine-readable JSON
Schema (draft 2020-12) for complete reports. All object fields are required, and
unknown fields are rejected. The helper implements only the schema's used keywords
with the standard library; it is not a general JSON Schema engine. Unsupported
keywords fail validation. Other consumers may use a full JSON Schema validator;
the additional consistency rules below still apply.

## Required sections

| JSON field | Contents |
| --- | --- |
| `schema_version`, `toolkit_version`, `toolkit_revision`, `synthetic` | Format/toolkit versions, inspected toolkit revision, and public-example marker |
| `project` | Name, ISO review date, revision/dirty state description, technology stack |
| `scope` | Target, mode, authorization, inclusions/exclusions, assets, entry points, trust boundaries, abuse cases |
| `controls` | Exactly SEC-01 through SEC-30 in order, applicability, requirement, status, reason, evidence, test references |
| `findings` | Classification, severity/impact, source evidence, recommended remediation, resolution and rationale |
| `fixes` | Finding reference, changed files, implementation summary, before/after test references, verification state |
| `tests` | Unique IDs, method, result, precise details, supporting file/line evidence |
| `tools` | Availability, execution state, version, exclusions/errors/limitations in details |
| `remaining_risks`, `limitations` | Unresolved exposure, unavailable evidence, and assessment boundaries |
| `release_recommendation` | Decision and bounded rationale; never a guarantee |

Use `F-001` for findings and `T-001` for tests/reviews. Evidence records contain a
target-relative `path`, a positive one-based `line`, and a concise `description`.
No absolute paths, traversal, or URLs in evidence paths. Runtime/manual evidence
can refer to an excluded local evidence file with the relevant line; record the
actual procedure and result. Validation of user reports does not read these source
files or authenticate their contents. Public fixture examples also check line bounds.

## Control statuses

| Status | Meaning and minimum evidence |
| --- | --- |
| PASS | Defined requirement was tested/reviewed; recorded evidence supports expected behavior within the scope. Applicability YES, evidence and passing test/review references required. |
| FAIL | Evidence demonstrates a requirement failure. Applicability YES, evidence plus a failed test/review or unresolved confirmed finding required. |
| NOT APPLICABLE | Architecture excludes the control in the selected scope. Applicability NO and a reason required. |
| UNVERIFIED | Insufficient evidence. Applicability YES or UNKNOWN; record the missing evidence and next action. |

Every control includes a nonempty requirement and reason. These are review areas:
a narrow fixture can pass an object-ownership check without proving every
authorization property. Do not extend a requirement's scope merely to increase
coverage. Code review is an accepted verification method when appropriate, but
label it accurately and do not call it a runtime test.

## Findings and fix states

- CONFIRMED: evidence supports the specific stated failure. OPEN or ACCEPTED RISK
  findings keep their control FAIL. Risk acceptance does not satisfy the requirement.
- POTENTIAL: a plausible issue needs more evidence. Keep it OPEN with its control
  UNVERIFIED (or FAIL if another confirmed issue demonstrates failure).
- FALSE POSITIVE: investigate and explain why the signal is not a vulnerability;
  resolution must be DISMISSED. Dismissing one alert does not make the control PASS.
- FIXED: a confirmed finding with a VERIFIED fix record. Include at least one failed
  before test/review and only passing after references, including legitimate behavior.
  Keep the original finding and its historical evidence. Set final control status from
  the current requirement verification, not from historical failure alone.
- An implemented but UNVERIFIED fix leaves the finding unresolved and the control
  FAIL. State what changed and what verification is still required.

Severity is Critical, High, Medium, Low, or Informational. Describe impact,
preconditions, affected actors/assets, and uncertainty. Do not invent CVSS scores,
loss estimates, exploitability, or credential validity.

## Local commands

Run from the toolkit root; replace the selected workspace path with the actual
target or separately authorized report workspace. Python 3.10+ is required for
helpers, with no pip dependencies.

```sh
python scripts/toolkit.py new --workspace /path/to/app --project-name "My app" --review-date 2026-10-09
python scripts/toolkit.py report --workspace /path/to/app --input .security-reports/audit.json --html
```

On Windows, use a quoted path such as `--workspace "E:\Projects\my-app"`. Edit the
private JSON skeleton with observed evidence. `new` runs no assessment: every
control starts UNVERIFIED. `report` validates and writes `report.redacted.json`,
`report.md`, and optionally `report.html` under `.security-reports/`. Both validate
before writing; invalid input exits 2. Use `--stem review-2` for another run;
overwrites are refused. Commands return 0 on completion. A completed renderer
does not mean the application's security controls passed.

Known sensitive values can be supplied as a JSON array in an excluded local file,
then masked with `--redact-file .security-reports/redactions.json`. Never put those
values on a command line or commit that file. Built-in masks cover common credential
assignments, bearer/basic headers, private-key blocks, credentialed URLs, selected
token prefixes, and JWT-shaped values. They are not exhaustive. Mask manually
first; review generated Markdown, JSON, and HTML before sharing. Source input is
never rewritten; it may still contain private data.

READY WITHIN SCOPE requires only PASS/NOT APPLICABLE controls and no unresolved
findings. Otherwise use REVIEW REQUIRED or HOLD and explain risk, missing checks,
and accountable next actions. This is a conservative consistency rule, not a
machine authorization to release.
