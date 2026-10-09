"""Rebuild public synthetic reports after running the local fixture tests.

Run from the toolkit root: python -m examples.build_examples
Never use this demonstration generator to assess a real application.
"""

from copy import deepcopy
import inspect
import io
from pathlib import Path
import unittest

from examples.fixtures import object_access, unsafe_config
from scripts import toolkit


def evidence(function, description):
    return {"path": "object_access.py", "line": inspect.getsourcelines(function)[1],
            "description": description}


def test_record(test_id, name, result, description, function):
    return {"id": test_id, "name": name, "method": "automated", "result": result,
            "details": description,
            "evidence": [evidence(function, "Exercised by tests/test_fixtures.py; see examples/README.md.")]}


def build_reports():
    controls = toolkit.load_controls()
    report = toolkit.new_report("Synthetic note lookup component", "2026-10-09", controls)
    report["synthetic"] = True
    report["toolkit_revision"] = "Synthetic v1.0.0 example; no measured toolkit revision"
    report["project"]["revision"] = "Synthetic side-by-side fixture variants; not a production revision"
    report["project"]["stack"] = ["Python standard library", "In-memory synthetic notes; no server or database"]
    report["scope"] = {
        "target": "examples/fixtures", "mode": "audit-only",
        "authorization": "Toolkit-owned pure local fixture tests and code review only",
        "included": ["secure_get_note ownership enforcement for two fixed synthetic identities"],
        "excluded": ["insecure_get_note retained as a regression precondition", "unsafe_config data fixture",
                     "Authentication, deployment, persistence, and all real applications"],
        "threat_model": {"assets": ["Synthetic Alice and Bob notes"],
                         "entry_points": ["Pure note-lookup function with trusted harness-supplied caller identity"],
                         "trust_boundaries": ["Caller identity and requested object ownership"],
                         "abuse_cases": ["Bob requests Alice's note by known object ID"]},
    }
    na_reasons = {
        1: "No SQL execution; only an in-memory dictionary.",
        2: "No browser rendering or DOM; returns a Python dictionary.",
        3: "No HTTP requests or ambient browser credentials.",
        4: "No file ingestion or processing.",
        6: "No untrusted service ingress or expensive resource operation in this pure function scope.",
        7: "No JWT issuance or consumption.", 8: "No credential handling in the selected secure function.",
        9: "No password handling or storage.", 10: "No authentication/MFA feature in this component.",
        11: "No CORS or HTTP responses.", 12: "No authentication-token storage.",
        13: "No separate role/privileged operation policy; object ownership is evaluated under SEC-05.",
        14: "No database or RLS model.", 15: "No inbound webhooks.", 16: "No server-side network requests.",
        17: "No browser build or source maps.", 18: "No bootstrap/development configuration in this selected function.",
        19: "No logging or diagnostic export in this component.", 20: "No third-party dependencies in this component.",
        21: "No domain workflow beyond the ownership invariant evaluated under SEC-05.",
        22: "No OAuth/OIDC integration.", 23: "No session management; callers are supplied by the harness.",
        24: "No HTTP/browser responses.", 25: "No sensitive network transport or persistent storage in this synthetic function.",
        26: "No deployment resources; this is explicitly a pure local component, not an unknown live deployment.",
        27: "CI pipeline is outside this explicitly selected application component.",
        28: "No mutation of shared state; function returns a copy.",
        29: "No durable state or recovery obligation for these disposable hard-coded synthetic notes.",
        30: "No application AI/agent feature; an AI-assisted reviewer does not change applicability.",
    }
    for index, control in enumerate(report["controls"], 1):
        if index != 5:
            control.update(applicability="NO", status="NOT APPLICABLE", reason=na_reasons[index])
    report["tests"] = [
        test_record("T-001", "Cross-user read is denied", "PASS",
                    "secure_get_note('bob', 'alice-note') raises PermissionError.", object_access.secure_get_note),
        test_record("T-002", "Owner read remains valid", "PASS",
                    "secure_get_note('alice', 'alice-note') returns Alice's synthetic note.", object_access.secure_get_note),
    ]
    report["controls"][4].update(
        applicability="YES", status="PASS", requirement="Lookup denies a different owner and permits the owner.",
        reason="Local fixture tests cover this narrow ownership requirement, not all authorization properties.",
        evidence=[evidence(object_access.secure_get_note, "Owner comparison precedes returning a copied note.")],
        test_refs=["T-001", "T-002"])
    report["tools"] = [{"name": name, "availability": "NOT CHECKED", "execution": "NOT RUN",
                        "version": "Not used", "details": "No scanner required for these fixture assertions; no scanner output is claimed."}
                       for name in ("semgrep", "gitleaks", "osv-scanner")]
    report["remaining_risks"] = ["No conclusion about any real application's release readiness."]
    report["limitations"] = ["Synthetic pure-function test scope only; no network, deployment, authentication, or persistence was assessed.",
                              "Expected failure in the unsafe variant is reproduced by a passing harness assertion; it is not a scanner result."]
    report["release_recommendation"] = {
        "decision": "READY WITHIN SCOPE", "rationale": "The selected protected function meets the narrow tested requirement; this is not approval to release an application."}
    clean = deepcopy(report)

    report["scope"]["included"] = ["insecure_get_note ownership behavior", "unsafe_config synthetic production-profile data"]
    report["scope"]["excluded"] = ["secure_get_note alternative implementation", "Any live debug endpoint or deployment", "All real applications"]
    report["tests"] = [test_record(
        "T-001", "Cross-user reads must be denied", "FAIL",
        "The local harness reproduces Bob reading Alice's note through insecure_get_note; the requirement fails.",
        object_access.insecure_get_note)]
    report["controls"][4].update(status="FAIL", test_refs=["T-001"],
                                  reason="A different caller obtains the other owner's note.",
                                  evidence=[evidence(object_access.insecure_get_note, "Caller is ignored in object lookup.")])
    config_line = next(i for i, line in enumerate(Path(unsafe_config.__file__).read_text(encoding="utf-8").splitlines(), 1)
                       if line.startswith("UNSAFE_CONFIG ="))
    config_evidence = {"path": "unsafe_config.py", "line": config_line,
                       "description": "Synthetic production profile sets debug True; no application consumes this data here."}
    report["controls"][17].update(
        applicability="YES", status="UNVERIFIED", requirement="A deployed production profile must not expose a debug interface.",
        reason="Risky configuration data exists, but there is no consuming service or deployment evidence.",
        evidence=[config_evidence])
    report["findings"] = [
        {"id": "F-001", "control_id": "SEC-05", "title": "Lookup ignores note ownership",
         "classification": "CONFIRMED", "severity": "High", "impact": "Within this fixture Bob reads Alice's synthetic note; no real data exists.",
         "evidence": [evidence(object_access.insecure_get_note, "Direct lookup does not constrain caller ownership.")],
         "remediation": "Use the owner-scoped secure_get_note variant and verify denial and legitimate owner access.",
         "resolution": "OPEN", "rationale": "Local function invocation demonstrates the exact cross-owner read."},
        {"id": "F-002", "control_id": "SEC-18", "title": "Debug-enabled production configuration may be unsafe if deployed",
         "classification": "POTENTIAL", "severity": "Medium", "impact": "A consuming server could expose diagnostics, but no such server or exposure is demonstrated.",
         "evidence": [config_evidence], "remediation": "Trace deployment consumption and require debug False for a real production profile.",
         "resolution": "OPEN", "rationale": "Agent/manual interpretation of configuration risk; exploitability is unverified."},
    ]
    report["remaining_risks"] = ["Confirmed cross-owner read in the unsafe variant.", "Debug configuration exposure requires consumer/deployment evidence."]
    report["release_recommendation"] = {"decision": "HOLD", "rationale": "Do not use the unsafe ownership variant; investigate configuration consumption before a real deployment."}
    mixed = deepcopy(report)

    report = deepcopy(clean)
    report["scope"]["mode"] = "audit-and-fix"
    report["scope"]["included"] = ["Illustrative replacement of insecure_get_note behavior with secure_get_note; F-001 only"]
    report["scope"]["authorization"] = "Synthetic local remediation demonstration for F-001; no real target was modified"
    report["tests"] = [deepcopy(mixed["tests"][0]),
                       {**deepcopy(clean["tests"][0]), "id": "T-002"},
                       {**deepcopy(clean["tests"][1]), "id": "T-003"}]
    report["controls"][4]["test_refs"] = ["T-002", "T-003"]
    report["findings"] = [{**deepcopy(mixed["findings"][0]), "resolution": "FIXED"}]
    report["fixes"] = [{"finding_id": "F-001", "summary": "Illustrative owner check in the secure variant; the deliberately unsafe variant remains solely as a test precondition.",
                        "changed_files": ["object_access.py"], "before_test_refs": ["T-001"],
                        "after_test_refs": ["T-002", "T-003"], "verification": "VERIFIED"}]
    report["limitations"].append("This before/after example compares two retained functions; it is not a claim of a historical production patch.")
    return {"narrow-pass": clean, "mixed-findings": mixed, "remediation": report}


def main():
    suite = unittest.defaultTestLoader.discover(str(toolkit.ROOT / "tests"), pattern="test_fixtures.py")
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    toolkit.require(result.wasSuccessful() and result.testsRun == 7, "Fixture verification failed")
    folder = toolkit.ROOT / "examples" / "reports"
    toolkit.require(not folder.is_symlink(), "Example directory cannot be a symlink")
    folder.mkdir(exist_ok=True)
    for stem, report in build_reports().items():
        toolkit.validate_report(report)
        toolkit.require(report == toolkit.redact(report), "Synthetic report needs redaction")
        outputs = {".json": toolkit.json.dumps(report, indent=2) + "\n",
                   ".md": toolkit.render_markdown(report)}
        for extension, content in outputs.items():
            path = folder / (stem + extension)
            toolkit.require(not path.is_symlink(), "Example output cannot be a symlink")
            path.write_text(content, encoding="utf-8", newline="\n")
    print(f"Ran {result.testsRun} local fixture tests; rebuilt 3 synthetic JSON/Markdown report pairs.")


if __name__ == "__main__":
    main()
