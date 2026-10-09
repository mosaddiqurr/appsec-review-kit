# Security review

SYNTHETIC EXAMPLE

Project: Synthetic note lookup component
Review date: 2026\-10\-09
Revision: Synthetic side\-by\-side fixture variants; not a production revision
Toolkit: 1.0.0; schema: 1
Toolkit revision: Synthetic v1\.0\.0 example; no measured toolkit revision

## Technology stack

- Python standard library
- In\-memory synthetic notes; no server or database

## Audit scope

Target: examples/fixtures
Mode: audit\-only
Authorization: Toolkit\-owned pure local fixture tests and code review only

Included:

- insecure\_get\_note ownership behavior
- unsafe\_config synthetic production\-profile data

Excluded:

- secure\_get\_note alternative implementation
- Any live debug endpoint or deployment
- All real applications

## Threat model

### Assets

- Synthetic Alice and Bob notes

### Entry Points

- Pure note\-lookup function with trusted harness\-supplied caller identity

### Trust Boundaries

- Caller identity and requested object ownership

### Abuse Cases

- Bob requests Alice's note by known object ID

## Control coverage

PASS: 0 | FAIL: 1 | NOT APPLICABLE: 28 | UNVERIFIED: 1

PASS applies only to the recorded requirement and evidence scope.

### SEC-01 — NOT APPLICABLE

Applicability: NO
Requirement: Keep untrusted data separate from SQL syntax\.
Rationale: No SQL execution; only an in\-memory dictionary\.
Tests/reviews: None

- None recorded.

### SEC-02 — NOT APPLICABLE

Applicability: NO
Requirement: Prevent untrusted input from becoming executable browser content\.
Rationale: No browser rendering or DOM; returns a Python dictionary\.
Tests/reviews: None

- None recorded.

### SEC-03 — NOT APPLICABLE

Applicability: NO
Requirement: Ensure state\-changing requests reflect the authenticated user's intent\.
Rationale: No HTTP requests or ambient browser credentials\.
Tests/reviews: None

- None recorded.

### SEC-04 — NOT APPLICABLE

Applicability: NO
Requirement: Constrain uploaded content, processing cost, and access\.
Rationale: No file ingestion or processing\.
Tests/reviews: None

- None recorded.

### SEC-05 — FAIL

Applicability: YES
Requirement: Lookup denies a different owner and permits the owner\.
Rationale: A different caller obtains the other owner's note\.
Tests/reviews: T-001

- object\_access\.py:13 — Caller is ignored in object lookup\.

### SEC-06 — NOT APPLICABLE

Applicability: NO
Requirement: Bound abuse and expensive resource consumption without blocking normal use\.
Rationale: No untrusted service ingress or expensive resource operation in this pure function scope\.
Tests/reviews: None

- None recorded.

### SEC-07 — NOT APPLICABLE

Applicability: NO
Requirement: Accept only authentic tokens intended for this issuer, audience, and use\.
Rationale: No JWT issuance or consumption\.
Tests/reviews: None

- None recorded.

### SEC-08 — NOT APPLICABLE

Applicability: NO
Requirement: Keep credentials out of public artifacts and minimize exposure\.
Rationale: No credential handling in the selected secure function\.
Tests/reviews: None

- None recorded.

### SEC-09 — NOT APPLICABLE

Applicability: NO
Requirement: Make stolen password databases expensive to attack and avoid credential disclosure\.
Rationale: No password handling or storage\.
Tests/reviews: None

- None recorded.

### SEC-10 — NOT APPLICABLE

Applicability: NO
Requirement: Protect high\-risk access and recovery with appropriately independent factors\.
Rationale: No authentication/MFA feature in this component\.
Tests/reviews: None

- None recorded.

### SEC-11 — NOT APPLICABLE

Applicability: NO
Requirement: Allow browser cross\-origin reads only where the application's policy intends them\.
Rationale: No CORS or HTTP responses\.
Tests/reviews: None

- None recorded.

### SEC-12 — NOT APPLICABLE

Applicability: NO
Requirement: Limit authentication\-token exposure to scripts, transport, and unrelated requests\.
Rationale: No authentication\-token storage\.
Tests/reviews: None

- None recorded.

### SEC-13 — NOT APPLICABLE

Applicability: NO
Requirement: Enforce role and operation permissions at trusted execution points\.
Rationale: No separate role/privileged operation policy; object ownership is evaluated under SEC\-05\.
Tests/reviews: None

- None recorded.

### SEC-14 — NOT APPLICABLE

Applicability: NO
Requirement: Make existing database row policies enforce intended tenant and user isolation\.
Rationale: No database or RLS model\.
Tests/reviews: None

- None recorded.

### SEC-15 — NOT APPLICABLE

Applicability: NO
Requirement: Accept authentic, fresh events and process retries without duplicate effects\.
Rationale: No inbound webhooks\.
Tests/reviews: None

- None recorded.

### SEC-16 — NOT APPLICABLE

Applicability: NO
Requirement: Prevent untrusted destinations from reaching unintended networks or credentials\.
Rationale: No server\-side network requests\.
Tests/reviews: None

- None recorded.

### SEC-17 — NOT APPLICABLE

Applicability: NO
Requirement: Prevent public debugging artifacts from disclosing information outside the intended public bundle\.
Rationale: No browser build or source maps\.
Tests/reviews: None

- None recorded.

### SEC-18 — UNVERIFIED

Applicability: YES
Requirement: A deployed production profile must not expose a debug interface\.
Rationale: Risky configuration data exists, but there is no consuming service or deployment evidence\.
Tests/reviews: None

- unsafe\_config\.py:3 — Synthetic production profile sets debug True; no application consumes this data here\.

### SEC-19 — NOT APPLICABLE

Applicability: NO
Requirement: Keep credentials and unnecessary personal data out of logs and diagnostics\.
Rationale: No logging or diagnostic export in this component\.
Tests/reviews: None

- None recorded.

### SEC-20 — NOT APPLICABLE

Applicability: NO
Requirement: Identify known vulnerable resolved components and assess realistic application exposure\.
Rationale: No third\-party dependencies in this component\.
Tests/reviews: None

- None recorded.

### SEC-21 — NOT APPLICABLE

Applicability: NO
Requirement: Enforce business invariants despite valid\-looking but adversarial workflows\.
Rationale: No domain workflow beyond the ownership invariant evaluated under SEC\-05\.
Tests/reviews: None

- None recorded.

### SEC-22 — NOT APPLICABLE

Applicability: NO
Requirement: Bind authorization responses and identities to the intended client, request, and account\.
Rationale: No OAuth/OIDC integration\.
Tests/reviews: None

- None recorded.

### SEC-23 — NOT APPLICABLE

Applicability: NO
Requirement: Bound session lifetime and invalidate sessions at relevant security events\.
Rationale: No session management; callers are supplied by the harness\.
Tests/reviews: None

- None recorded.

### SEC-24 — NOT APPLICABLE

Applicability: NO
Requirement: Use browser security policies suited to the content and deployment\.
Rationale: No HTTP/browser responses\.
Tests/reviews: None

- None recorded.

### SEC-25 — NOT APPLICABLE

Applicability: NO
Requirement: Protect sensitive data in transit and at rest with an appropriate key lifecycle\.
Rationale: No sensitive network transport or persistent storage in this synthetic function\.
Tests/reviews: None

- None recorded.

### SEC-26 — NOT APPLICABLE

Applicability: NO
Requirement: Limit infrastructure access and exposure to required subjects and resources\.
Rationale: No deployment resources; this is explicitly a pure local component, not an unknown live deployment\.
Tests/reviews: None

- None recorded.

### SEC-27 — NOT APPLICABLE

Applicability: NO
Requirement: Prevent untrusted changes from gaining trusted build credentials or publication authority\.
Rationale: CI pipeline is outside this explicitly selected application component\.
Tests/reviews: None

- None recorded.

### SEC-28 — NOT APPLICABLE

Applicability: NO
Requirement: Preserve security and business invariants under concurrent operations\.
Rationale: No mutation of shared state; function returns a copy\.
Tests/reviews: None

- None recorded.

### SEC-29 — NOT APPLICABLE

Applicability: NO
Requirement: Make recovery data confidential, access\-controlled, and demonstrably restorable\.
Rationale: No durable state or recovery obligation for these disposable hard\-coded synthetic notes\.
Tests/reviews: None

- None recorded.

### SEC-30 — NOT APPLICABLE

Applicability: NO
Requirement: Constrain untrusted model inputs and actions at enforceable trust boundaries\.
Rationale: No application AI/agent feature; an AI\-assisted reviewer does not change applicability\.
Tests/reviews: None

- None recorded.

## Findings

### F-001: Lookup ignores note ownership

CONFIRMED | High | OPEN | SEC-05
Impact: Within this fixture Bob reads Alice's synthetic note; no real data exists\.
Classification rationale: Local function invocation demonstrates the exact cross\-owner read\.
Remediation: Use the owner\-scoped secure\_get\_note variant and verify denial and legitimate owner access\.

- object\_access\.py:13 — Direct lookup does not constrain caller ownership\.

### F-002: Debug\-enabled production configuration may be unsafe if deployed

POTENTIAL | Medium | OPEN | SEC-18
Impact: A consuming server could expose diagnostics, but no such server or exposure is demonstrated\.
Classification rationale: Agent/manual interpretation of configuration risk; exploitability is unverified\.
Remediation: Trace deployment consumption and require debug False for a real production profile\.

- unsafe\_config\.py:3 — Synthetic production profile sets debug True; no application consumes this data here\.

## Implemented fixes

None.

## Test and review results

### T-001: Cross\-user reads must be denied

automated | FAIL
The local harness reproduces Bob reading Alice's note through insecure\_get\_note; the requirement fails\.

- object\_access\.py:13 — Exercised by tests/test\_fixtures\.py; see examples/README\.md\.

## Optional tools

- semgrep: NOT CHECKED; NOT RUN; version Not used; No scanner required for these fixture assertions; no scanner output is claimed\.
- gitleaks: NOT CHECKED; NOT RUN; version Not used; No scanner required for these fixture assertions; no scanner output is claimed\.
- osv\-scanner: NOT CHECKED; NOT RUN; version Not used; No scanner required for these fixture assertions; no scanner output is claimed\.

## Remaining Risks

- Confirmed cross\-owner read in the unsafe variant\.
- Debug configuration exposure requires consumer/deployment evidence\.

## Limitations

- Synthetic pure\-function test scope only; no network, deployment, authentication, or persistence was assessed\.
- Expected failure in the unsafe variant is reproduced by a passing harness assertion; it is not a scanner result\.

## Release recommendation

HOLD

Do not use the unsafe ownership variant; investigate configuration consumption before a real deployment\.

This report is a bounded assessment, not a security guarantee or certification.
