# Publication checklist and v1.0.0 notes

AppSec Review Kit 1.0.0 is intended for
[mosaddiqurr/appsec-review-kit](https://github.com/mosaddiqurr/appsec-review-kit).
Publication requires an explicit user/maintainer instruction; the toolkit's
helpers never commit, push, tag, or deploy. A release assessment covers the toolkit,
not the security of applications reviewed with it.

## Before publication

1. Review the [README](../README.md), [controls](../checks/README.md), prompts,
   [safety boundaries](safety.md), and [validation evidence](validation.md).
2. Confirm version 1.0.0, MIT attribution, the canonical repository URL, and an
   complete universal prompts below the README introduction and at its end, both
   identical to `prompts/universal.md`.
3. Regenerate the guide and examples when their sources change, then run validation
   and tests. Validation checks local Markdown file and heading links offline;
   official external references need a separate reference review.
4. Inspect the exact staged file list and content for secrets, private reports,
   caches, and unintended files. Use an established secret detector when available;
   record its absence and never describe pattern review as an executed scanner.
5. Check remotes and existing remote history before initializing or publishing.
   Preserve user changes, avoid force-pushing, and stop on authentication or remote
   conflicts. Do not rewrite history to work around a failed push.
6. Enable GitHub private vulnerability reporting and review Actions permissions.
   The included workflow uses read-only contents access, immutable action pins,
   and offline toolkit tests without secrets or publication jobs.

## Authorized publication commands

Run from the toolkit root after the checks above. Initialize Git only if this
folder has no repository, and add origin only if absent. For an existing remote,
inspect and reconcile its history before pushing; the commands below assume an
empty remote or an already compatible branch. Stage public paths explicitly.

```sh
python scripts/toolkit.py render-checks
python -m examples.build_examples
python scripts/toolkit.py validate
python -m unittest discover -s tests -v
git init -b main
git remote add origin https://github.com/mosaddiqurr/appsec-review-kit.git
git add README.md AGENTS.md CLAUDE.md LICENSE CONTRIBUTING.md SECURITY.md CHANGELOG.md VERSION .gitignore .gitattributes .github prompts checks scripts templates examples docs tests
git status --short
git diff --cached --check
git diff --cached --stat
git diff --cached
git commit -m "feat: release AppSec Review Kit v1.0.0"
git push -u origin main
git rev-parse HEAD
git ls-remote origin refs/heads/main
```

Confirm the remote branch SHA matches the local commit before reporting success.
Inspect hosted CI for that commit; configuration alone is not a successful run.
Record the actual commit, push, and CI results in the publication handoff, rather
than hard-coding a moving branch's status into this checklist.

A version file is not a Git tag or GitHub release. Once the version's functionality
and hosted CI pass, a maintainer can separately authorize tagging and creating a
release. Do not tag incomplete or failing work. Never attach private audit evidence.

## v1.0.0 release notes

AppSec Review Kit provides a reusable application security review workflow for AI
coding agents. It includes 30 applicability-aware review areas, portable Codex and
Claude Code prompts, audit-only and selected remediation modes, and evidence-based
private reporting.

Optional Python standard-library helpers validate registry/report structure,
create UNVERIFIED skeletons, redact/render JSON and Markdown, and produce an
escaped standalone HTML text view. Optional scanner documentation covers Semgrep,
Gitleaks, OSV-Scanner, and framework checks; helpers do not install, execute, or
import results from scanners. Two local fixtures and three synthetic report pairs
demonstrate ownership checks, potential configuration risk, and before/after
verification.

Validation includes control completeness, report consistency, generated content,
evidence line bounds, local Markdown file/heading links, and synchronized universal-prompt
copy sections. It does not authenticate evidence or prove exploitability. Business
rules, deployment, recovery, and release decisions require owner evidence. Scanners
and AI fixes have limitations; the kit does not guarantee security or certification.

See [validation evidence](validation.md), [security limitations](../README.md#security-limitations),
and the [changelog](../CHANGELOG.md). Licensed under [MIT](../LICENSE).
