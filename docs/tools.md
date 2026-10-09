# Optional established tools

The toolkit never installs or launches a scanner. Check availability with:

```sh
python scripts/toolkit.py tools
```

This performs PATH lookup only; AVAILABLE is not a scan or a verified version.
Check executable provenance before running `--version` or `--help`. Record missing
tools as MISSING/NOT RUN in reports and continue appropriate manual review. Never
turn a missing check into PASS. Syntax below was checked against official docs on
2026-10-09; use the installed version's help and record differences.

Run commands from the selected target root after reviewing configuration and
effects. Replace `.` with a bounded selected path if needed. First ensure
`.security-reports/` exists and is excluded from version control. Keep console
output and report files private; scanner output may contain source or credentials.

## Semgrep Community Edition

For local static analysis using reviewed, already downloaded rules:

```sh
semgrep scan --config /path/to/reviewed-rules.yml --oss-only --metrics=off --disable-version-check --json --output .security-reports/semgrep.json .
```

Review rules/configuration and ignore/exclusion settings. Avoid autofix, local build
execution, remote validators, and logged-in dashboard workflows by default. Registry
rules require a network fetch; `--config auto` can disclose a project URL, and
registry usage may enable metrics. The explicit options above disable metrics and
version checking but are not an OS network sandbox. Confirm behavior for the
installed version and use egress restrictions if strict offline operation is required.
Scanner output needs data-flow/context review. [CLI reference](https://semgrep.dev/docs/cli-reference)

Optional installation: use an isolated Python environment and the official
[installation guide](https://semgrep.dev/docs/getting-started/quickstart).
Do not install globally or assume native Windows support; follow current platform
requirements (an approved WSL/container environment may be needed).

## Gitleaks

Use current v8 directory and Git-history commands, rather than deprecated `detect`:

```sh
gitleaks dir --redact=100 --report-format json --report-path .security-reports/gitleaks-files.json .
gitleaks git --redact=100 --report-format json --report-path .security-reports/gitleaks-history.json .
```

History mode requires a local Git repository and only covers available history.
Do not fetch remote history implicitly. Review `.gitleaks.toml`, ignore lists,
environment configuration, and which files were excluded. Full redaction reduces
secret exposure but report/source fields still require private handling and manual
inspection. Exit 1 can mean leaks **or an error**; inspect completion state before
interpreting it. Never validate discovered credentials against their providers.
[Commands, redaction, configuration, exit codes, and installation](https://github.com/gitleaks/gitleaks)

Optional installation: select an official release binary for the platform, verify
published integrity information, and place it in a user-approved local tools folder.

## OSV-Scanner v2

For supported dependency files:

```sh
osv-scanner scan source --recursive --format json --output-file .security-reports/osv.json .
```

Normal operation can query external vulnerability/package services and disclose
package inventory. Obtain authorization for that flow. For offline use, provision
the required database separately with authorized network access and use the
installed version's offline-vulnerability options; record cache age and failures.
Do not enable database downloads, builds, or call analysis implicitly. A missing
database or unsupported lockfile leaves coverage UNVERIFIED. Review advisories
against resolved versions and runtime exposure. [Usage and offline options](https://google.github.io/osv-scanner/usage/)

Optional installation: use an official prebuilt binary from the
[project's installation links](https://github.com/google/osv-scanner#basic-installation).
Do not substitute v1 flags for v2 syntax.

## Framework and package-manager checks

Use the installed framework's official documentation and reviewed project setup.
For example, npm's documented audit facility sends dependency information to a
registry; it is not automatically an offline check. Framework deployment checks
may import application code. Review those effects and the user's authorization
before running them. Record versions, exact commands, exits, and missing coverage.
Do not run automatic audit fixes, update lockfiles, install dependencies, or execute
package lifecycle hooks in audit-only mode. [npm audit documentation](https://docs.npmjs.com/cli/commands/npm-audit)

No-warning results prove only that the selected tool/rules reported no warning in
their stated scope. They do not verify all 30 controls or guarantee security.
