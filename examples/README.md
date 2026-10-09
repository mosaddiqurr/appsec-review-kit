# Synthetic examples and reproducible evidence

All examples are fictional and local. No credentials, personal data, server,
database, network scan, or production patch is involved. Do not expose the
deliberately unsafe fixture as a service.

| Example | What it demonstrates |
| --- | --- |
| [Narrow pass](reports/narrow-pass.md) / [JSON](reports/narrow-pass.json) | No confirmed findings within a single protected note-lookup ownership requirement; 29 other areas are outside this component's architecture |
| [Mixed findings](reports/mixed-findings.md) / [JSON](reports/mixed-findings.json) | Confirmed cross-owner read plus a potential unsafe debug configuration with no deployed consumer evidence |
| [Remediation](reports/remediation.md) / [JSON](reports/remediation.json) | Failed ownership requirement in the unsafe variant; verified denial and legitimate owner access in the secure variant |

The [object-access fixture](fixtures/object_access.py) retains an unsafe function
that ignores the caller and a protected function that checks ownership. Caller
identities come from a trusted local test harness; this is not a complete
authentication/authorization implementation. The [configuration fixture](fixtures/unsafe_config.py)
contains synthetic debug configuration and an obvious non-credential marker.

Run the actual behavioral checks:

```sh
python -m unittest discover -s tests -p test_fixtures.py -v
python -m examples.build_examples
python scripts/toolkit.py validate
```

The generator runs the seven fixture tests before rebuilding the three report
pairs. Examples use a fixed illustrative review date for deterministic output.
The tests and generator do not run Semgrep, Gitleaks, or OSV-Scanner. Example tools
are NOT CHECKED/NOT RUN rather than fabricated scanner output. The development
machine's separate availability check is documented in [research notes](../docs/research.md).

Automated assertions reproduce the unsafe cross-user read and verify the protected
function's denial, owner access, missing/anonymous rejection, and copy semantics.
The unit harness passes when it reproduces the deliberate flaw; the corresponding
security requirement is accurately recorded as FAIL in the mixed/before report.
Debug-flag values are checked automatically, but the potential exposure and
applicability/severity decisions require agent/manual reasoning. No live debug
exposure is claimed. The synthetic marker is not a usable credential.

Remediation compares two side-by-side functions, not Git history or a real
production change. Its final scope includes only the protected function;
the vulnerable variant remains an excluded test precondition. The mixed example's
configuration issue remains unresolved and is excluded from the narrow remediation
scope, not silently treated as fixed. The tests reproduce evidence behind the
examples; they do not demonstrate that an arbitrary AI agent detects these issues.
