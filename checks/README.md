# Security control guide

30 review areas, not 30 presumed vulnerabilities. Select applicability from the target architecture.

Generated from [controls.json](controls.json). Edit that registry, then run `python scripts/toolkit.py render-checks` from the toolkit root.

Use with [the workflow](../docs/workflow.md) and [reporting contract](../docs/reporting.md).

## SEC-01: SQL Injection

**Objective:** Keep untrusted data separate from SQL syntax.

**Technology/architecture:** SQL databases, ORMs with raw query escape hatches

**Applies when:** The application constructs or executes SQL using externally influenced data.

**Not applicable when:** There is no SQL query execution in the selected scope.

**Failure Patterns:**

- String interpolation in queries
- Assuming ORM use makes raw SQL safe
- User-controlled identifiers or sort clauses

**Detection:**

- Trace request, job, and import inputs to query sinks; inspect stored procedures too.
- Distinguish bound values from dynamic identifiers and inspect driver parameter APIs.

**Tools:**

- Semgrep with reviewed language rules
- Local database test harness

**Remediation:**

- Bind data values using driver parameters.
- Allowlist identifiers and sort directions; reduce database account privileges.

**Verification:**

- Test an injection-shaped value against a local seeded database and show it is treated as data.
- Assert ordinary queries still return only intended rows.

**Severity considerations:** Often High; increase with unauthenticated access, broad read/write privileges, or sensitive data. Syntax warnings alone do not establish impact.

**Automation limitations:** Static matches need data-flow and driver semantics review; live database permissions and reachable routes may be unavailable.

**References:**

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

## SEC-02: Cross-Site Scripting

**Objective:** Prevent untrusted input from becoming executable browser content.

**Technology/architecture:** HTML templates, Browser DOM, Rich-text rendering

**Applies when:** Untrusted data reaches browser-rendered HTML, script, URL, or DOM contexts.

**Not applicable when:** No browser-rendered content exists in scope.

**Failure Patterns:**

- Unsafe HTML insertion
- Context-inappropriate escaping
- Trusting stored content or disabling template escaping

**Detection:**

- Trace reflected, persisted, and client-side sources to rendering sinks.
- Review sanitizer configuration and unsafe URL schemes in the correct context.

**Tools:**

- Semgrep with relevant browser/framework rules
- Local browser tests

**Remediation:**

- Use framework contextual escaping and safe DOM APIs.
- Sanitize intentionally supported HTML with a maintained sanitizer; use CSP as defense in depth.

**Verification:**

- Exercise reflected, stored, and DOM routes locally with harmless execution markers.
- Check legitimate rich content and URL rendering are preserved.

**Severity considerations:** Usually Medium to High depending on victim privileges, reach, and accessible data; self-only execution may have lower impact.

**Automation limitations:** Server-only scans miss client flows and browser behavior; CSP presence alone does not prove XSS prevention.

**References:**

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## SEC-03: Cross-Site Request Forgery

**Objective:** Ensure state-changing requests reflect the authenticated user's intent.

**Technology/architecture:** Cookie authentication, Browser ambient credentials

**Applies when:** A browser automatically attaches credentials to state-changing requests, including session cookies or HTTP authentication.

**Not applicable when:** Endpoints require non-ambient credentials and do not accept ambient-authenticated alternatives; document that evidence.

**Failure Patterns:**

- Missing CSRF validation
- State changes via GET
- Relying solely on CORS or loosely configured SameSite

**Detection:**

- Inventory credential mechanisms per endpoint, including login and alternate form content types.
- Review token binding, origin checks, and framework CSRF middleware coverage.

**Tools:**

- Framework test client
- Local cross-origin browser harness

**Remediation:**

- Use framework CSRF tokens or robust origin verification suited to the architecture.
- Use appropriate SameSite cookies as additional protection; avoid state-changing safe methods.

**Verification:**

- Show a legitimate action succeeds and missing/invalid anti-CSRF evidence is rejected.
- Test cross-origin form requests and login CSRF where relevant.

**Severity considerations:** Medium to High when unwanted actions change accounts, privileges, or funds; assess prerequisites and browser cookie behavior.

**Automation limitations:** CORS does not stop simple cross-origin requests. Bearer-only APIs generally differ from cookie sessions; deployment behavior needs browser validation.

**References:**

- [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
- [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## SEC-04: File Upload Security

**Objective:** Constrain uploaded content, processing cost, and access.

**Technology/architecture:** Multipart uploads, Object storage, Image/document processors

**Applies when:** Users or integrations can submit files or archives for storage or processing.

**Not applicable when:** No file ingestion exists in the selected scope.

**Failure Patterns:**

- Extension-only validation
- Executable public storage or path traversal
- Unbounded decompression or processor resource use

**Detection:**

- Inspect upload handlers, storage names, serving headers, and processor invocation.
- Review allowed formats, size/count limits, malware strategy, and authorization.

**Tools:**

- Local upload tests
- Reviewed content-type parsers
- Maintained malware tools when available

**Remediation:**

- Allowlist required formats and validate content with suitable parsers; MIME headers are untrusted.
- Generate storage identifiers, isolate storage from execution, enforce quotas, and sandbox processors.

**Verification:**

- Use benign mismatched formats, traversal names, and bounded oversized inputs.
- Verify downloads enforce authorization and valid files still work.

**Severity considerations:** High for code execution or cross-user data exposure; resource exhaustion and unsafe active content vary with deployment.

**Automation limitations:** A parser or antivirus result cannot prove a file harmless; processor versions, serving behavior, and storage policy require review.

**References:**

- [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
- [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

## SEC-05: Broken Object-Level Authorization

**Objective:** Enforce ownership and tenant boundaries for every object operation.

**Technology/architecture:** Multi-user APIs, Tenant-scoped data, Background object access

**Applies when:** Callers access objects identified by IDs, paths, or other selectors.

**Not applicable when:** There are no caller-dependent object access rules in scope.

**Failure Patterns:**

- Lookup by ID without caller scope
- Cross-tenant writes or deletes
- Authorization on UI lists but not direct or batch endpoints

**Detection:**

- Trace read/write/delete/export paths from identity to object selection.
- Build a subject-object-action matrix for owners, other users, tenants, and administrators.

**Tools:**

- Two-user local regression tests
- Agent-assisted data-flow review

**Remediation:**

- Scope lookups to authorized subjects/tenants and enforce policy server-side.
- Cover nested, batch, and asynchronous operations; opaque IDs supplement authorization.

**Verification:**

- Assert owner access succeeds and another user/tenant is denied without data leakage.
- Test every applicable action and role, including legitimate administrator behavior.

**Severity considerations:** High for sensitive cross-user or tenant access; impact depends on accessible data and write powers, not ID guessability alone.

**Automation limitations:** Scanners rarely know ownership policy. Manual policy definition and at least two identities are normally required.

**References:**

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
- [Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

## SEC-06: Rate Limiting

**Objective:** Bound abuse and expensive resource consumption without blocking normal use.

**Technology/architecture:** Authentication endpoints, APIs, Expensive jobs and exports

**Applies when:** Untrusted callers can repeatedly invoke authentication, costly operations, or scarce resources.

**Not applicable when:** No repeatable untrusted entry point or constrained resource exists in scope.

**Failure Patterns:**

- IP-only limits behind shared proxies
- Unbounded queues, pagination, or payloads
- Limits inconsistent across instances

**Detection:**

- Identify abuse-sensitive actions and cost drivers; inspect gateway and application controls.
- Check identity/IP/device dimensions, trusted proxy handling, quotas, and failure behavior.

**Tools:**

- Local fake-clock tests
- Bounded concurrency harness

**Remediation:**

- Use layered limits and quotas by appropriate subjects, with bounded payloads, queues, and execution time.
- Avoid account lockouts that enable denial of service; return usable retry information.

**Verification:**

- Use a small bounded local burst to show enforcement and recovery.
- Verify normal usage and multi-instance/shared-store assumptions without production load testing.

**Severity considerations:** Medium to High for account takeover facilitation, large costs, or outages; required thresholds depend on the service.

**Automation limitations:** Source review cannot establish safe production capacity, distributed enforcement, or abuse thresholds; never stress a live service by default.

**References:**

- [CWE-770](https://cwe.mitre.org/data/definitions/770.html)
- [Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

## SEC-07: JWT Security

**Objective:** Accept only authentic tokens intended for this issuer, audience, and use.

**Technology/architecture:** JWT libraries, JWKS, Signed access or identity tokens

**Applies when:** The application issues or consumes JWTs.

**Not applicable when:** No JWTs are used; opaque sessions need separate review.

**Failure Patterns:**

- Algorithm confusion or unsigned tokens
- Missing issuer/audience/expiry checks
- Arbitrary key URLs or token-type confusion

**Detection:**

- Review verification options, algorithm allowlists, key provenance, and claim validation.
- Separate ID tokens from access tokens and review key rotation and caching.

**Tools:**

- JWT library tests
- Reviewed Semgrep rules

**Remediation:**

- Use maintained libraries with explicit algorithms and trusted keys.
- Validate required issuer, audience, expiration, and token purpose; constrain clock skew and key selection.

**Verification:**

- Reject tampered, expired, wrong-audience, wrong-issuer, and unexpected-algorithm tokens.
- Accept a valid intended token and exercise key rotation locally.

**Severity considerations:** High if authentication or privilege claims can be forged; shorten severity claims when only speculative library usage is known.

**Automation limitations:** Decoding is not verification. Library defaults differ; revocation and key lifecycle require operational evidence.

**References:**

- [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
- [JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)

## SEC-08: Secret and API Key Exposure

**Objective:** Keep credentials out of public artifacts and minimize exposure.

**Technology/architecture:** Source and configuration, Browser bundles, Local Git history

**Applies when:** The project uses credentials or may have included them in source or artifacts.

**Not applicable when:** No credential-bearing feature/artifact exists, with bounded inventory evidence; unknown history remains unverified.

**Failure Patterns:**

- Committed credentials
- Server secrets embedded in browser builds
- Secrets in history, examples, or build output

**Detection:**

- Review tracked files, ignored-config practices, generated public assets, and available local history.
- Classify synthetic placeholders separately; never test a discovered credential against its provider.

**Tools:**

- Gitleaks dir and git modes with redaction
- Agent review of public bundle inputs

**Remediation:**

- Revoke and rotate exposed credentials through the owner's approved process.
- Move secrets to suitable runtime storage; history cleanup alone does not revoke a credential.

**Verification:**

- Verify the current artifact no longer exposes the value and configuration loads correctly.
- Obtain owner evidence of revocation and assess history/copies; mask evidence.

**Severity considerations:** High to Critical for usable privileged credentials; an obvious synthetic value is not evidence of a valid secret.

**Automation limitations:** Patterns miss opaque secrets and can flag examples. Local history may be shallow; credential validity must not be probed without explicit authorization.

**References:**

- [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
- [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

## SEC-09: Password Storage

**Objective:** Make stolen password databases expensive to attack and avoid credential disclosure.

**Technology/architecture:** Password-based authentication, Password migration and reset flows

**Applies when:** The application stores or verifies user passwords.

**Not applicable when:** Authentication is fully delegated and the application never handles passwords; review the identity provider boundary separately.

**Failure Patterns:**

- Plaintext or reversible password storage
- Fast unsalted hashes
- Passwords in logs, exceptions, or reset messages

**Detection:**

- Inspect hashing API, salt generation, work factors, pepper handling, and rehash-on-login logic.
- Trace password handling through registration, reset, import, and error paths.

**Tools:**

- Framework password utilities
- Local verifier tests

**Remediation:**

- Use a maintained adaptive password hash, preferably Argon2id with parameters appropriate to resources.
- Follow current framework/OWASP guidance for legacy bcrypt limits and migration; never implement custom cryptography.

**Verification:**

- Check unique salts, supported cost parameters, successful/failed verification, and safe migration.
- Confirm password values are absent from captured logs.

**Severity considerations:** High for plaintext/reversible storage; weak work factors depend on realistic offline attack cost and exposed data.

**Automation limitations:** Parameter strength changes with hardware and policy; unit tests cannot demonstrate resistance to all offline attacks.

**References:**

- [CWE-916](https://cwe.mitre.org/data/definitions/916.html)
- [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## SEC-10: Multi-Factor Authentication

**Objective:** Protect high-risk access and recovery with appropriately independent factors.

**Technology/architecture:** Privileged accounts, Identity providers, MFA enrollment and recovery

**Applies when:** Risk, contract, or policy requires MFA, particularly for privileged or sensitive actions.

**Not applicable when:** No MFA requirement is justified by the documented risk model; absence alone is not automatically a vulnerability.

**Failure Patterns:**

- Enrollment without recent authentication
- Weak recovery bypass
- Reusable OTPs or unenforced administrator policy

**Detection:**

- Review enforced IdP/application policy, enrollment, step-up, recovery, and factor reset.
- Check phishing resistance, replay protection, attempt limits, and recovery notifications.

**Tools:**

- Local mocked-IdP tests
- Manual identity-provider configuration review

**Remediation:**

- Prefer phishing-resistant factors where supported; enforce policy on every relevant route.
- Secure reset/recovery to comparable assurance and provide a safe recovery procedure.

**Verification:**

- Test required-role enforcement, one-time use, invalid attempts, and legitimate recovery.
- Verify factor removal and enrollment require appropriate authentication.

**Severity considerations:** High for bypass of required privileged MFA; missing optional MFA needs a documented risk assessment before classification.

**Automation limitations:** Source alone may not show IdP policy; account recovery and support processes need human review.

**References:**

- [CWE-308](https://cwe.mitre.org/data/definitions/308.html)
- [Multifactor Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

## SEC-11: CORS Security

**Objective:** Allow browser cross-origin reads only where the application's policy intends them.

**Technology/architecture:** Browser APIs, Reverse proxies, Cross-origin integrations

**Applies when:** The service returns CORS headers or supports cross-origin browser access.

**Not applicable when:** No browser cross-origin access or CORS policy exists in scope.

**Failure Patterns:**

- Reflecting arbitrary origins with credentials
- Overly broad trusted subdomains
- Inconsistent preflight and actual-response policy

**Detection:**

- Review origin parsing, allowlists, credential use, and proxy-added headers.
- Distinguish public unauthenticated APIs from responses containing private user data.

**Tools:**

- Local header assertions
- Browser-based cross-origin tests

**Remediation:**

- Use exact required origins including scheme and port, with narrow methods and headers.
- Enable credentials only when required; emit Vary: Origin for dynamically selected origins.

**Verification:**

- Test allowed and disallowed origins, null origin, preflight, and actual requests.
- Verify authenticated private data cannot be read by an untrusted origin.

**Severity considerations:** Medium to High when private data is readable; wildcard origin on a public credential-free API may be intentional.

**Automation limitations:** CORS is a browser read boundary, not authentication or CSRF prevention. Browsers reject wildcard Allow-Origin with credentialed reads; that pair alone is not proof of data theft.

**References:**

- [CWE-942](https://cwe.mitre.org/data/definitions/942.html)
- [HTML5 Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)

## SEC-12: Authentication Token Storage

**Objective:** Limit authentication-token exposure to scripts, transport, and unrelated requests.

**Technology/architecture:** Browser cookies, Browser storage, Native secure storage

**Applies when:** Clients or servers persist authentication tokens.

**Not applicable when:** There are no persisted authentication tokens within the selected scope.

**Failure Patterns:**

- Long-lived tokens in localStorage without an assessed tradeoff
- Missing Secure/HttpOnly cookie flags
- Broad cookie domain or token exposure in URLs

**Detection:**

- Inventory each token, lifetime, storage location, consumer, and trust boundary.
- Review cookie scope, SameSite needs, mobile secure storage, and frontend XSS exposure.

**Tools:**

- Browser storage/cookie inspection on a local test instance
- Configuration review

**Remediation:**

- Prefer protected cookies where suitable, with Secure, HttpOnly, and appropriate SameSite/scope.
- Account for CSRF when moving to cookies; use platform secure storage for native clients and minimize token lifetime.

**Verification:**

- Assert relevant cookie flags and scope, and confirm scripts cannot read HttpOnly tokens.
- Test legitimate login/cross-site flows; ensure URLs and logs contain no tokens.

**Severity considerations:** Medium to High depending on token privilege, lifetime, and attacker capabilities; storage choice alone does not demonstrate an exploit.

**Automation limitations:** HttpOnly does not stop all actions through an XSS-compromised page. Browser and native storage models differ; design tradeoffs require review.

**References:**

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html)
- [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

## SEC-13: Server-Side Authorization

**Objective:** Enforce role and operation permissions at trusted execution points.

**Technology/architecture:** Server routes, Service methods, Jobs and administrative APIs

**Applies when:** Operations have role-, permission-, or policy-dependent access.

**Not applicable when:** No privileged or identity-dependent operations exist in the selected scope.

**Failure Patterns:**

- UI-only role checks
- Unprotected alternate routes or HTTP methods
- Trusting client-supplied roles or tenant claims

**Detection:**

- Inventory privileged operations and map policy to middleware and service-layer checks.
- Review default-deny behavior, mass assignment, job invocation, and alternate interfaces.

**Tools:**

- Local role-matrix tests
- Agent-assisted route review

**Remediation:**

- Enforce trusted server-side policy with deny-by-default behavior.
- Centralize reusable policy decisions while checking each entry point and writable property.

**Verification:**

- Test anonymous, ordinary, and privileged callers across routes and methods.
- Verify forbidden fields are ignored/rejected and authorized workflows remain usable.

**Severity considerations:** High to Critical for privileged state changes; separate operation-level authorization from object ownership in SEC-05.

**Automation limitations:** Route decorators alone do not prove complete policy enforcement; business roles and internal trust assumptions need owner input.

**References:**

- [CWE-862](https://cwe.mitre.org/data/definitions/862.html)
- [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

## SEC-14: Database Row-Level Security

**Objective:** Make existing database row policies enforce intended tenant and user isolation.

**Technology/architecture:** Databases using row security, Direct database clients, Policy-based tenant isolation

**Applies when:** The architecture uses RLS, or explicitly relies on database row policies for isolation.

**Not applicable when:** The architecture does not use or require RLS; assess application-level access using SEC-05 and SEC-13.

**Failure Patterns:**

- Overbroad USING/WITH CHECK expressions
- Application role bypasses policies
- Missing write policies or unsafe tenant context

**Detection:**

- Inspect migrations and effective policies with the actual application database role.
- Review owners, superusers, BYPASSRLS, FORCE ROW LEVEL SECURITY, pooling, and trusted identity context.

**Tools:**

- Local database integration tests
- Read-only policy catalog queries

**Remediation:**

- Constrain read and write policies to the intended identity/tenant model.
- Avoid bypass-capable application roles; bind trusted per-request context safely, including pooled connections.

**Verification:**

- Test cross-tenant reads, inserts, updates, and deletes using the real application role.
- Verify connection reuse cannot retain another tenant's identity and legitimate operations succeed.

**Severity considerations:** High for cross-tenant access under a relied-on policy; missing RLS alone is not a finding.

**Automation limitations:** Policy behavior is vendor-specific. Schema text cannot establish effective production role privileges or managed-service identity settings.

**References:**

- [CWE-863](https://cwe.mitre.org/data/definitions/863.html)
- [Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

## SEC-15: Webhook Verification

**Objective:** Accept authentic, fresh events and process retries without duplicate effects.

**Technology/architecture:** Payment webhooks, Signed event callbacks, Integration consumers

**Applies when:** External services deliver events that influence application state.

**Not applicable when:** No inbound webhook/event-callback boundary exists.

**Failure Patterns:**

- Signature over reserialized body
- Missing timestamp/replay checks
- Duplicate delivery repeats financial effects

**Detection:**

- Review provider-specific verification over exact raw bytes before processing.
- Trace secret lookup, timestamp tolerance, event IDs, retries, and transactional idempotency.

**Tools:**

- Provider's maintained SDK
- Local signed-event test vectors

**Remediation:**

- Use the provider's verification library and approved secret rotation.
- Enforce suitable freshness/replay rules and atomic idempotency keyed to trusted event identity.

**Verification:**

- Reject tampered bodies, invalid signatures, and stale events as appropriate to the protocol.
- Replay and concurrently deliver a valid event; verify one effect and safe legitimate retry.

**Severity considerations:** High for payment/account manipulation; distinguish signature authenticity, replay detection, and business idempotency.

**Automation limitations:** Not every provider signs timestamps; follow its protocol rather than inventing headers. Static checks cannot verify provider configuration.

**References:**

- [CWE-294](https://cwe.mitre.org/data/definitions/294.html)
- [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

## SEC-16: Server-Side Request Forgery

**Objective:** Prevent untrusted destinations from reaching unintended networks or credentials.

**Technology/architecture:** URL fetchers, Importers, Proxy and preview services

**Applies when:** Untrusted input influences a server-side network destination.

**Not applicable when:** No server-side fetching destination is externally influenced.

**Failure Patterns:**

- Scheme-only validation
- Redirect bypass of allowlists
- DNS rebinding or access to metadata/private addresses

**Detection:**

- Trace URLs through parsing, DNS resolution, redirects, proxies, and connection APIs.
- Inspect egress restrictions, credential forwarding, and supported schemes/ports.

**Tools:**

- Local mock HTTP/DNS services
- Semgrep with reviewed SSRF rules

**Remediation:**

- Prefer exact known destinations and narrow protocols/ports.
- Enforce resolved-address and redirect policy at connection time; isolate egress and strip unintended credentials.

**Verification:**

- Use local mocks for forbidden private/metadata destinations and redirect changes; never probe real metadata services.
- Verify intended destinations work and rebinding/IPv6 normalization cases are addressed.

**Severity considerations:** High to Critical when internal services or cloud credentials become reachable; simple URL acceptance alone is insufficient.

**Automation limitations:** Correct DNS/connection enforcement depends on the HTTP client and deployment network. Static analysis often cannot prove runtime destination safety.

**References:**

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
- [Server Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## SEC-17: Source Map Exposure

**Objective:** Prevent public debugging artifacts from disclosing information outside the intended public bundle.

**Technology/architecture:** JavaScript/CSS builds, Public static assets, Error tracking

**Applies when:** Production builds generate source maps or publish debugging artifacts.

**Not applicable when:** There are no production source maps or browser bundles in scope.

**Failure Patterns:**

- Publishing embedded private source or credentials
- Guessable unreferenced map URLs
- Assuming disabling sourceMappingURL removes deployed files

**Detection:**

- Review build configuration and the actual local release artifact.
- Determine whether map contents add sensitive information beyond already-public code and inspect upload destination controls.

**Tools:**

- Local artifact inspection
- Build configuration review

**Remediation:**

- Remove sensitive values from all client builds, regardless of source maps.
- Restrict source maps to trusted error tracking or publish intentionally only after content review.

**Verification:**

- Inspect generated release files and authorized deployment evidence for direct map access.
- Verify debugging still works through the intended restricted channel.

**Severity considerations:** Informational to High according to actual disclosed content; source-map presence alone is not automatically a vulnerability.

**Automation limitations:** Source maps can be intentionally public. Local build settings do not prove CDN contents or cache invalidation.

**References:**

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
- [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

## SEC-18: Default Credentials

**Objective:** Prevent deployment with known passwords, bootstrap accounts, or unsafe development modes.

**Technology/architecture:** Bootstrap scripts, Admin accounts, Runtime configuration

**Applies when:** The application provisions accounts or includes development/bootstrap configuration.

**Not applicable when:** No account provisioning or environment-sensitive development configuration exists in scope.

**Failure Patterns:**

- Shared default administrator password
- Debug mode enabled in production profile
- Fail-open fallback when required configuration is absent

**Detection:**

- Review install/bootstrap paths, sample configuration, and environment defaults.
- Inspect whether provisioning secrets must be changed and development services are exposed.

**Tools:**

- Configuration inspection
- Local production-profile unit tests

**Remediation:**

- Require unique securely provisioned credentials and disable unnecessary defaults.
- Make production configuration fail closed without echoing secrets; isolate development profiles.

**Verification:**

- Show an unchanged default is refused or cannot access privileged resources.
- Test missing required settings and legitimate secure production-profile startup locally.

**Severity considerations:** High to Critical for exposed privileged defaults; insecure-looking settings unused outside a local fixture need context.

**Automation limitations:** Runtime provisioning and deployment overrides may be invisible; do not try default passwords against live systems without authorization.

**References:**

- [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html)
- [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## SEC-19: Sensitive Information in Logs

**Objective:** Keep credentials and unnecessary personal data out of logs and diagnostics.

**Technology/architecture:** Application logs, Traces, CI output, Error reporting

**Applies when:** The application emits operational logs, traces, or diagnostics.

**Not applicable when:** No logging/diagnostic surface exists in the selected scope, with evidence.

**Failure Patterns:**

- Whole request/body logging
- Tokens in URLs or exception objects
- Sensitive tracing attributes sent to third parties

**Detection:**

- Trace authentication and sensitive data through loggers, middleware, and exporters.
- Review redaction before serialization, access, retention, and log injection handling.

**Tools:**

- Local captured-log tests
- Reviewed secret-scanner output

**Remediation:**

- Use structured allowlisted logging and redact at the earliest shared boundary.
- Restrict log access/retention and avoid logging raw credentials or request bodies by default.

**Verification:**

- Exercise success/error paths with synthetic markers and inspect captured outputs.
- Verify useful request identifiers remain and multiline input cannot forge log records.

**Severity considerations:** High for usable credentials in accessible logs; personal-data impact depends on sensitivity, retention, and readership.

**Automation limitations:** Redaction patterns cannot cover all secret or personal-data formats; external log storage and historical deletion require human evidence.

**References:**

- [CWE-532](https://cwe.mitre.org/data/definitions/532.html)
- [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

## SEC-20: Vulnerable Dependencies

**Objective:** Identify known vulnerable resolved components and assess realistic application exposure.

**Technology/architecture:** Package manifests, Lockfiles, Vendored dependencies, Runtime/build dependencies

**Applies when:** The application depends on third-party components, directly or transitively.

**Not applicable when:** No third-party components are used in the selected scope; platform dependencies may remain outside scope.

**Failure Patterns:**

- Unreviewed vulnerable versions
- Manifest/lockfile drift
- Ignoring build-time or transitive dependencies

**Detection:**

- Inventory actual resolved versions, supported lockfiles, vendored code, and deployment runtime.
- Review advisory conditions, reachability, compensating controls, and scan database freshness.

**Tools:**

- OSV-Scanner v2
- Reviewed framework/package-manager audit commands

**Remediation:**

- Upgrade to supported fixed versions and review migration impact.
- Use a documented compensating control or time-bounded exception when no safe upgrade exists.

**Verification:**

- Recheck resolved artifacts against the advisory and run affected legitimate behavior tests.
- Record scanner/database version, exclusions, failures, and residual advisories.

**Severity considerations:** Use advisory severity as input, then assess installed version, exposure, and exploit prerequisites; tool ratings are not automatic application severity.

**Automation limitations:** Offline databases age; scanners miss unknown flaws and unsupported ecosystems. No advisory does not prove safety; a version match need not establish exploitability.

**References:**

- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html)
- [Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)

## SEC-21: Business Logic Vulnerabilities

**Objective:** Enforce business invariants despite valid-looking but adversarial workflows.

**Technology/architecture:** Payments, Discounts, Approval flows, Account linking and entitlements

**Applies when:** The application enforces domain-specific rules or workflows.

**Not applicable when:** No security-relevant business invariant exists in the selected component.

**Failure Patterns:**

- Trusting client prices or discount eligibility
- Skipping approval/order states
- Negative quantities, replayed credits, or rounding abuse

**Detection:**

- Ask the owner for invariants and forbidden outcomes; map trust in external inputs.
- Review state machines, payment reconciliation, currency/quantity boundaries, and bypass routes.

**Tools:**

- Domain-focused local tests
- Manual abuse-case review

**Remediation:**

- Recompute authoritative values server-side and constrain state transitions.
- Use explicit validation, transactional invariants, and trusted payment reconciliation.

**Verification:**

- Test forbidden transitions, altered price/quantity, replay, and boundary cases.
- Verify legitimate refunds, retries, approvals, and failure recovery still work.

**Severity considerations:** High to Critical for unauthorized transfers or entitlements; quantify business impact with the owner rather than inventing loss estimates.

**Automation limitations:** Scanners cannot infer product rules. Missing business context is UNVERIFIED; passing happy-path tests is insufficient.

**References:**

- [CWE-841](https://cwe.mitre.org/data/definitions/841.html)
- [Abuse Case](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html)

## SEC-22: OAuth and OpenID Connect Security

**Objective:** Bind authorization responses and identities to the intended client, request, and account.

**Technology/architecture:** OAuth 2.0 clients, OIDC relying parties, External account linking

**Applies when:** The application implements OAuth/OIDC login, delegation, or account linking.

**Not applicable when:** No OAuth or OpenID Connect integration exists.

**Failure Patterns:**

- Loose redirect URI matching
- Missing request/response binding
- Account linking based on unverified email or unvalidated ID tokens

**Detection:**

- Review exact registered redirects, code flow, PKCE S256, and CSRF/request binding.
- For OIDC validate signature, issuer, audience, expiry, and nonce where required; distinguish access and ID tokens.

**Tools:**

- Maintained OAuth/OIDC library tests
- Local mocked authorization server

**Remediation:**

- Follow current OAuth security BCP and provider requirements using maintained libraries.
- Prefer authorization code with PKCE; validate state or a protocol-appropriate CSRF binding and require authenticated intent for linking.

**Verification:**

- Reject wrong state/binding, incorrect PKCE verifier, unexpected redirects, and invalid identity claims.
- Exercise normal login, denial, logout implications, and explicit account linking.

**Severity considerations:** High to Critical for account takeover or token theft; judge protocol-specific defenses instead of requiring every mechanism in every flow.

**Automation limitations:** Identity-provider registrations and redirect behavior need configuration evidence; state and nonce serve different purposes.

**References:**

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html)
- [OAuth2](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [RFC 9700 OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)

## SEC-23: Session Management

**Objective:** Bound session lifetime and invalidate sessions at relevant security events.

**Technology/architecture:** Server sessions, Cookies, Refresh tokens, Stateless token sessions

**Applies when:** The application maintains authenticated state across requests.

**Not applicable when:** No authenticated persistent state exists in scope.

**Failure Patterns:**

- Session fixation
- Logout only removes a UI token
- Unlimited idle/absolute lifetime or unsafe refresh reuse

**Detection:**

- Trace session creation, identifier rotation, expiry, logout, password changes, and privilege changes.
- Review refresh token rotation/reuse detection and distributed invalidation.

**Tools:**

- Local fake-clock and session tests
- Configuration review

**Remediation:**

- Rotate identifiers after authentication/privilege changes and use suitable idle/absolute expiry.
- Invalidate server-side sessions where supported; for stateless tokens document revocation strategy and residual lifetime.

**Verification:**

- Test fixation attempts, expiry boundaries, logout reuse, and relevant security-event revocation.
- Verify ordinary session renewal and concurrent device behavior follow policy.

**Severity considerations:** Medium to High according to session privilege and residual attacker access; stateless-token logout limitations need explicit risk treatment.

**Automation limitations:** Source review does not prove distributed revocation or session-store behavior; client deletion does not invalidate stolen stateless tokens.

**References:**

- [CWE-613](https://cwe.mitre.org/data/definitions/613.html)
- [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

## SEC-24: HTTP Security Headers

**Objective:** Use browser security policies suited to the content and deployment.

**Technology/architecture:** HTML responses, TLS reverse proxies, Embedded browser content

**Applies when:** The application serves browser content or HTTPS endpoints where relevant policies apply.

**Not applicable when:** The reviewed component serves no applicable HTTP/browser response; evaluate each header separately.

**Failure Patterns:**

- Missing/ineffective CSP on risky HTML
- Clickjacking-sensitive pages freely frameable
- HSTS applied without verifying HTTPS subdomain readiness

**Detection:**

- Review effective headers at application/proxy boundaries across success/error responses.
- Assess CSP sources/nonces, frame-ancestors or X-Frame-Options, nosniff, referrer policy, and HSTS requirements.

**Tools:**

- Local response-header tests
- Authorized deployed header inspection

**Remediation:**

- Deploy an appropriate CSP and frame policy, testing integrations first.
- Use HSTS only with operational HTTPS readiness; review includeSubDomains/preload impacts before enabling.

**Verification:**

- Verify actual responses and error paths, browser CSP behavior, and permitted embeds.
- Ensure restrictive policies do not break legitimate scripts or required framing.

**Severity considerations:** Often Low to Medium alone; increase only with demonstrated exploit context. HSTS and CSP relevance differs for non-browser APIs.

**Automation limitations:** A generic header score is not an application assessment. CSP report-only is observation, and deprecated headers are not a substitute for current protections.

**References:**

- [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)
- [HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

## SEC-25: Transport and Data Encryption

**Objective:** Protect sensitive data in transit and at rest with an appropriate key lifecycle.

**Technology/architecture:** TLS clients/servers, Data stores, Key management services

**Applies when:** Sensitive data crosses network boundaries or persists in storage.

**Not applicable when:** No sensitive network transmission or storage exists in the selected scope.

**Failure Patterns:**

- Disabled certificate validation
- Plaintext sensitive transport/storage
- Encryption keys stored beside broadly readable ciphertext

**Detection:**

- Map sensitive flows and storage including caches, backups, and service-to-service links.
- Review TLS validation, current library defaults, key access, rotation, and recovery procedures.

**Tools:**

- Local TLS/configuration tests
- Read-only KMS/storage policy review

**Remediation:**

- Use supported TLS with certificate/hostname verification and maintained cryptographic libraries.
- Use authenticated encryption/storage services where appropriate; separate key access and plan rotation/recovery.

**Verification:**

- Reject invalid certificates with a local test endpoint; test intended trust chains.
- Verify encrypted storage configuration and unauthorized key denial without printing plaintext or keys.

**Severity considerations:** High for interceptable sensitive data or broad key access; at-rest requirements depend on threat model and data classification.

**Automation limitations:** Application code cannot prove cloud disk encryption, backup protection, or key custody. Encryption does not replace authorization.

**References:**

- [CWE-319](https://cwe.mitre.org/data/definitions/319.html)
- [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## SEC-26: Cloud and Infrastructure Permissions

**Objective:** Limit infrastructure access and exposure to required subjects and resources.

**Technology/architecture:** IAM, Infrastructure as code, Containers, Object storage

**Applies when:** The application has deployment infrastructure or cloud resources in scope.

**Not applicable when:** The selected component has no deployment resources in its documented architecture. If a deployment exists but effective settings are unavailable, use UNVERIFIED.

**Failure Patterns:**

- Public sensitive storage
- Wildcard IAM or overly privileged service accounts
- Exposed management ports or privileged containers

**Detection:**

- Review IaC, role trust policies, network boundaries, storage ACLs, and workload identities.
- Compare intended permissions to available read-only effective-policy evidence and drift records.

**Tools:**

- Reviewed IaC scanner if installed
- Manual IAM/network policy review

**Remediation:**

- Reduce permissions to required actions/resources and isolate public/private surfaces.
- Prefer scoped workload identity over static credentials; stage policy changes with rollback access.

**Verification:**

- Use local policy tests or authorized policy simulation to check allowed/denied actions.
- Have operators confirm effective deployed state and legitimate workload behavior.

**Severity considerations:** High to Critical for sensitive public resources or administrative access; broad-looking policy syntax needs effective-context review.

**Automation limitations:** IaC may differ from deployment, and effective IAM is compositional. Do not enumerate accounts or change infrastructure without explicit scope.

**References:**

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html)
- [Infrastructure as Code Security](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

## SEC-27: CI/CD Pipeline Security

**Objective:** Prevent untrusted changes from gaining trusted build credentials or publication authority.

**Technology/architecture:** GitHub Actions, Build pipelines, Artifact publishing

**Applies when:** The project builds, tests, or releases through a CI/CD pipeline.

**Not applicable when:** No pipeline/build-automation boundary exists in scope.

**Failure Patterns:**

- Privileged jobs execute untrusted pull-request code
- Shell interpolation of untrusted event data
- Mutable action refs or persistent broad credentials

**Detection:**

- Trace event triggers, permissions, checkout refs, third-party actions, caches, artifacts, and release gates.
- Review whether build/install hooks run before trust is established and whether logs expose credentials.

**Tools:**

- Workflow code review
- Reviewed workflow linter when installed

**Remediation:**

- Use minimal permissions, immutable reviewed action pins, and isolated untrusted jobs.
- Pass untrusted values as data rather than shell code; gate publication and restrict reusable credentials.

**Verification:**

- Inspect representative fork-PR and trusted-release execution paths without publishing.
- Run local workflow checks and verify untrusted jobs cannot access release secrets.

**Severity considerations:** High to Critical when arbitrary changes reach secrets or releases; action pinning alone cannot make untrusted code safe.

**Automation limitations:** Hosted settings, environment protection, and runner persistence need owner evidence; do not execute suspicious workflows to test them.

**References:**

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html)
- [CI CD Security](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)

## SEC-28: Race Conditions

**Objective:** Preserve security and business invariants under concurrent operations.

**Technology/architecture:** Payments, Inventory, One-time tokens, Ownership transitions

**Applies when:** Concurrent requests can alter a shared security-sensitive resource.

**Not applicable when:** No shared mutable state or concurrency-sensitive invariant exists in scope.

**Failure Patterns:**

- Check-then-act without atomicity
- Duplicate redemption/payment effects
- In-memory locks in a multi-process deployment

**Detection:**

- Identify invariants, transaction boundaries, unique constraints, locks, and retry handling.
- Review isolation level and external side effects under concurrent retries.

**Tools:**

- Bounded local concurrency tests
- Local database transaction tests

**Remediation:**

- Use atomic updates, suitable transactions/locks, and database uniqueness constraints.
- Couple idempotency to durable state and reconcile external effects; avoid process-only locks for distributed systems.

**Verification:**

- Coordinate a small number of local workers against the same operation.
- Assert at most one effect and expected losers/retries, then verify normal sequential use.

**Severity considerations:** High for double spending or privilege/ownership bypass; quantify whether duplicates violate an actual invariant.

**Automation limitations:** Passing stress tests does not prove absence of races. Isolation semantics and real deployment topology require reasoning and integration evidence.

**References:**

- [CWE-362](https://cwe.mitre.org/data/definitions/362.html)
- [Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)

## SEC-29: Backup and Recovery Security

**Objective:** Make recovery data confidential, access-controlled, and demonstrably restorable.

**Technology/architecture:** Database backups, Snapshots, Recovery runbooks

**Applies when:** The service stores durable state or has backup/recovery obligations.

**Not applicable when:** The selected component is stateless with no recovery data or obligation; missing backup evidence for a stateful system is UNVERIFIED.

**Failure Patterns:**

- Public/unprotected backup archives
- Unrecoverable encryption keys
- Untested restores or retention that conflicts with policy

**Detection:**

- Review backup access/encryption, retention, separation from compromised production identities, and documented RPO/RTO.
- Inspect dated restore evidence and dependency/key recovery plans; never restore over production.

**Tools:**

- Backup configuration review
- Approved isolated restore exercise

**Remediation:**

- Protect backup data and keys with scoped access, monitored recovery procedures, and suitable isolation/immutability.
- Define retention and perform documented restores in an isolated environment.

**Verification:**

- Use synthetic data for a bounded restore drill and verify integrity and access denial.
- Record measured recovery behavior against owner-defined objectives and remaining dependencies.

**Severity considerations:** High for sensitive backup disclosure or inability to recover critical data; RPO/RTO adequacy is an owner decision.

**Automation limitations:** Repository files cannot prove backups exist or restore successfully. Restoration is potentially destructive and requires an explicitly approved isolated destination.

**References:**

- [CWE-530](https://cwe.mitre.org/data/definitions/530.html)
- [Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

## SEC-30: AI and Agent Security

**Objective:** Constrain untrusted model inputs and actions at enforceable trust boundaries.

**Technology/architecture:** LLM features, RAG, Tool-using agents, MCP and retrieval integrations

**Applies when:** The application uses AI models, agent tools, retrieval, or model-driven actions.

**Not applicable when:** The application has no AI or agent feature; using this toolkit to review it does not make SEC-30 applicable.

**Failure Patterns:**

- Retrieved text treated as authority
- Broad tool access or implicit approval
- Secrets in prompts, traces, or model-triggered requests

**Detection:**

- Map untrusted direct/retrieved inputs to model context, tool calls, memory, and output consumers.
- Review per-user authorization at tool execution, sandbox boundaries, egress, sensitive data, and approval gates.

**Tools:**

- Local mocked-model/tool tests
- Agent-assisted trust-boundary review

**Remediation:**

- Enforce least privilege and authorization outside the model; require approval for consequential actions.
- Treat model output as untrusted, minimize secrets, isolate tools, and constrain destinations and data access.

**Verification:**

- Use benign direct/indirect injection text with mocked tools to attempt unauthorized access/actions.
- Verify trusted runtime policy blocks it while intended actions succeed; record tested attack scope.

**Severity considerations:** High to Critical when untrusted text can trigger privileged actions or data exfiltration; model compliance alone is insufficient evidence.

**Automation limitations:** Prompt wording or injection tests cannot prove complete resistance. Tool permissions, data boundaries, human approvals, and changing model behavior need separate validation.

**References:**

- [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html)
- [LLM Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
