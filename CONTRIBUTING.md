# Contributing

Contributions should make reviews more accurate, reproducible, or easier to use.
Useful changes include precise applicability, framework-specific pitfalls, current
official references, safe fixture tests, and corrections to misleading guidance.

## Local development

Use Python 3.10+; there are no required pip packages or API keys. From the root:

```sh
python scripts/toolkit.py render-checks
python -m examples.build_examples
python scripts/toolkit.py validate
python -m unittest discover -s tests -v
```

The first command regenerates the public guide from `checks/controls.json`.
Rebuild examples only when their synthetic data or renderer changes. The second
command runs local fixture assertions and writes public synthetic examples;
it is not a real assessment. All other tests are local/offline and must not
contact targets, install packages, execute arbitrary project hooks, or require secrets.

## Control and report changes

- Keep SEC-01 through SEC-30 stable and unique for version 1. Preserve exactly
  30 core controls; propose coverage extensions with a compatibility rationale.
- Include applicability and exclusion conditions, failure patterns, concrete review
  steps, safe remediation, appropriate verification, severity reasoning, relevant
  official references, and automation limits. Do not infer vulnerability from a
  feature's mere presence or absence.
- Edit the canonical JSON registry; do not hand-edit its generated Markdown.
  Check source dates and version-specific standard IDs. Avoid copying third-party text.
- Keep JSON Schema and its dependency-free subset validator aligned. Add tests
  for meaningful format/consistency changes and rejection of unsupported keywords.
  Treat report-format changes as compatibility decisions, not incidental refactors.
- Use synthetic identities/data and local-only fixtures. Add a failure reproduction
  and legitimate behavior verification for fixes when feasible. Never submit real
  target reports, credentials, personal data, or unnecessary private source snippets.
- Do not add a database, remote backend, paid-key dependency, unreviewed global
  installer, or homemade vulnerability scanner to this prompt-first toolkit.

## Pull requests

Describe the problem, resulting behavior, relevant references, and actual tests run.
Disclose unexecuted checks and known limitations. Preserve the shared workflow
across README, prompts, AGENTS, and CLAUDE instructions. Avoid duplicate guidance
when a clear relative link suffices. Keep both complete README prompt blocks identical
to `prompts/universal.md`; validation rejects drift or misplaced copy sections.
Check all local Markdown links with validation.

Security-sensitive issues follow [SECURITY.md](SECURITY.md); do not put exploit
details or private reports in public issues. Maintainers should review action pins,
permissions, tool data flows, and filesystem boundaries before accepting changes.
Contributions are provided under the project's [MIT license](LICENSE).
