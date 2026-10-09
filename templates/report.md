# Private security review

Use this outline when Python is unavailable. Follow [the report contract](../docs/reporting.md)
for the companion JSON and status meanings. Store completed reports only in the
selected excluded output directory. Replace each instruction below with observations.

## Project and scope

Record project name, review date, target revision/dirty state, toolkit revision,
mode, authorization, technology stack, reviewed paths, and exclusions.

## Threat model

Describe assets, actors, entry points, trust boundaries, and business abuse cases.

## Control coverage

Account for SEC-01 through SEC-30 using the [control guide](../checks/README.md).
For each: applicability, stated requirement, PASS/FAIL/NOT APPLICABLE/UNVERIFIED,
reason, minimal file:line evidence, verification results, and missing evidence.

## Findings

For each candidate: ID, control ID, CONFIRMED/POTENTIAL/FALSE POSITIVE, severity
reasoning, impact and prerequisites, minimal evidence, classification rationale,
recommended remediation, and OPEN/FIXED/ACCEPTED RISK/DISMISSED resolution.
Explicitly state when there are no confirmed findings within the selected scope.

## Implemented fixes

Record selected scope, changed files, change summary, failing-before evidence,
passing-after regression and legitimate behavior checks, and verification state.
Keep unverified changes and original finding evidence visible.

## Tests and tools

Record actual commands/procedures, versions/rules/database dates, results, errors,
missing tools, exclusions, and checks NOT RUN. Do not fabricate execution output.

## Remaining risks and limitations

Describe deployment/business evidence still needed, coverage limits, risk owners,
and next actions. Redact all credentials; avoid unnecessary private source excerpts.

## Release recommendation

Choose HOLD, REVIEW REQUIRED, or READY WITHIN SCOPE and justify the bounded decision.
State that this is not certification or a guarantee of complete security.
