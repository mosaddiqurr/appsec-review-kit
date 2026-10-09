# Changelog

## 1.0.0 — 2026-10-10

Initial release. See [validation evidence](docs/validation.md) for executed checks
and [release guidance](docs/release.md) for publication requirements.

- Add 30 applicability-aware security control definitions with official references,
  detection/review methods, remediation, verification, and automation limits.
- Add universal, audit-only, and scoped audit-and-fix prompts with shared Codex/Claude
  compatibility instructions and explicit execution/evidence boundaries.
- Add dependency-free Python helpers for registry/report validation, private report
  skeletons, redacted JSON/Markdown, optional escaped standalone HTML, and tool lookup.
- Document optional Semgrep, Gitleaks, OSV-Scanner, and framework checks without
  automatic installation, execution, or unsupported scanner-result claims.
- Add two local fixtures and three reproducible, explicitly synthetic report examples.
- Add offline unittest coverage, generated-file/local-link validation, and a GitHub
  Actions workflow with immutable action pins and read-only repository permissions.
- Validate local Markdown heading links and keep complete universal prompt blocks
  directly below the README introduction and at its end, identical to the canonical
  prompt. Both use GitHub's native fenced-code copy control.
- Standardize AppSec Review Kit branding, repository references, and grouped
  README coverage while preserving the 30 control IDs and report schema version 1.
- Document contribution, disclosure, limitations, and explicit publication steps.

No service, database, paid AI API key, automatic publishing, or claim of security
certification is introduced.
