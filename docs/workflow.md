# Review workflow

The prompts and [30-control guide](../checks/README.md) are the product. Helpers
are optional. Neither a model nor a scanner decides business policy by itself.

## 1. Select and obtain

Select one target root, audit-only or a bounded audit-and-fix scope, and any
authorized isolated fixtures. Never infer permission to scan an entire disk,
other repositories, cloud accounts, or production. Confirm the intended folder
from the user's instruction and current directory; ask only if ambiguous.

Retrieve this toolkit through an available repository/file facility or use an
existing local copy. Record its revision and read its entry point, this workflow,
[safety policy](safety.md), control guide, and [report contract](reporting.md).
Inspect downloaded helpers before running them. If retrieval is blocked, request
a local copy and stop applying this toolkit; do not invent its contents. A reviewed
immutable revision improves reproducibility but is not a trust guarantee.

## 2. Establish evidence and scope

Inventory languages, manifests/lockfiles, frameworks, entry points, authentication,
stores, external services, CI/IaC, uploads, background tasks, and AI features from
bounded file inspection. Do not execute package manifests to identify the stack.
Record the target revision/dirty state without exposing private diffs in public logs.
Describe assets, actors, entry points, trust boundaries, and important abuse cases.
Obtain business-rule or deployment context only when it affects a conclusion.

Create a private report directory, ensuring it is excluded from version control.
This toolkit's `.gitignore` does not automatically apply to another repository.
In audit-only mode, do not edit that target's ignore file: use an already ignored
location or the user's designated excluded workspace and record the target path.
For a read-only target, a separate selected report workspace can hold reports;
do not copy private source there unnecessarily.

Account for every SEC-01 through SEC-30. Record the specific requirement reviewed
and whether applicability is YES, NO, or UNKNOWN. Mark absent features NOT
APPLICABLE with a reason. Mark absent evidence UNVERIFIED. In particular:

- No SQL execution: SEC-01 can be NOT APPLICABLE.
- No uploads: SEC-04 can be NOT APPLICABLE.
- No RLS model: SEC-14 can be NOT APPLICABLE; still assess authorization.
- No application AI feature: SEC-30 can be NOT APPLICABLE even when an AI agent reviews it.
- Unknown deployment or IdP settings: UNVERIFIED, not assumed absent or safe.

## 3. Review and check

Choose review methods for each applicable control. Inspect commands, scripts,
hooks, dependencies, configuration, output destinations, and network behavior
before execution. Review [tool instructions](tools.md); a PATH match only indicates
availability. Do not install tools silently or run target code to discover what it does.

Use read-only local checks first. A test that writes caches, databases, or artifacts
needs an authorized disposable local environment. Never use a live service as the
default fixture. Record tool versions/configuration, exact commands, completion
state, exclusions, and database/rule dates where available. Raw scanner output may
contain secrets/source; keep it private and review it before sharing with any service.

Trace source to sink, confirm framework semantics, and evaluate reachable behavior.
Reproduce issues only with benign, bounded inputs in authorized environments.
Classify candidates as CONFIRMED, POTENTIAL, or FALSE POSITIVE. A version advisory
may confirm a vulnerable installed component while runtime exploitability remains
unknown; describe precisely what was demonstrated. Keep unresolved alerts and
missing evidence visible. Do not create findings simply to fill all 30 areas.

## 4. Report

Use [the Markdown template](../templates/report.md), or create structured input
with `scripts/toolkit.py new`. Write Markdown and JSON to a selected private output
workspace. Include scope, threat model, all controls, evidence, severity reasoning,
recommended fixes, test outcomes, tool state, limitations, residual risks, and a
release recommendation. Validation checks consistency; it cannot authenticate
evidence or decide whether a test was sufficient.

Use PASS only for a stated requirement supported by executed tests or documented
manual/code review. FAIL requires demonstrated failure. NOT APPLICABLE requires
architecture justification. UNVERIFIED never becomes PASS because time or tools
were unavailable. Preserve narrow scope in every conclusion; no numerical security
score or claim of certification is produced.

## 5. Remediate only in the selected scope

Audit-only ends with options. In audit-and-fix, restate the user's selected scope
and proceed with authorized reversible local changes. If selection is missing,
provide concrete finding IDs and request selection before editing. Preserve user
changes and prefer an isolated branch/copy without discarding or automatically
stashing existing work. Changes to this toolkit are a separate maintenance task.

For each confirmed in-scope issue, record a safe failure reproduction, minimal fix,
changed paths, regression results, and legitimate behavior tests. A fix is VERIFIED
only with failing-before and passing-after evidence appropriate to the requirement.
Use separate test records for each stage. Reassess the control using after evidence;
do not erase the original finding. If verification is missing, record an UNVERIFIED
fix and keep the finding OPEN/FAIL. Escalate migration, rotation, restoration, and
production decisions with concrete operator steps; never silently deploy.

## 6. Handoff

Recommend HOLD, REVIEW REQUIRED, or READY WITHIN SCOPE with a rationale, risk owner,
and next actions in narrative text. The helper permits READY WITHIN SCOPE only when
every applicable requirement passes and there are no unresolved findings. Human
release owners may accept risk using REVIEW REQUIRED and a documented decision;
the helper does not approve releases. List deployment, business-context, recovery,
and other checks that need human verification.
