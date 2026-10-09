"""Offline contract, privacy, and filesystem regression tests."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from examples.build_examples import build_reports
from scripts import toolkit as t


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.controls = t.load_controls()

    def test_exact_ids_and_unique_names(self):
        self.assertEqual([c["id"] for c in self.controls], list(t.CONTROL_IDS))
        self.assertEqual(len({c["name"] for c in self.controls}), 30)

    def test_missing_and_extra_controls_rejected(self):
        for controls in (self.controls[:-1], self.controls + [self.controls[0]]):
            with self.assertRaises(t.ValidationError):
                t.validate_controls(controls)

    def test_duplicate_id_rejected(self):
        self.controls[1]["id"] = "SEC-01"
        with self.assertRaises(t.ValidationError):
            t.validate_controls(self.controls)

    def test_all_required_fields_and_nonempty_metadata(self):
        for field in self.controls[0]:
            controls = deepcopy(self.controls)
            del controls[0][field]
            with self.subTest(field=field), self.assertRaises(t.ValidationError):
                t.validate_controls(controls)
        for field in ("objective", "detection", "verification", "references", "tools"):
            controls = deepcopy(self.controls)
            controls[0][field] = "" if field == "objective" else []
            with self.subTest(field=field), self.assertRaises(t.ValidationError):
                t.validate_controls(controls)

    def test_applicability_requires_both_branches(self):
        for value in ({"when": "SQL"}, {"when": " ", "not_applicable_when": "None"}, [], None):
            self.controls[0]["applicability"] = value
            with self.subTest(value=value), self.assertRaises(t.ValidationError):
                t.validate_controls(self.controls)

    def test_important_architecture_distinctions_are_documented(self):
        self.assertIn("non-ambient", self.controls[2]["applicability"]["not_applicable_when"])
        self.assertIn("does not use or require RLS", self.controls[13]["applicability"]["not_applicable_when"])
        self.assertIn("not automatically a vulnerability", self.controls[16]["severity"])
        self.assertIn("does not make SEC-30 applicable", self.controls[29]["applicability"]["not_applicable_when"])

    def test_reference_source_must_be_official(self):
        self.controls[0]["references"][0]["url"] = "https://example.invalid/claim"
        with self.assertRaises(t.ValidationError):
            t.validate_controls(self.controls)

    def test_generated_guide_is_current(self):
        self.assertEqual((t.ROOT / "checks" / "README.md").read_text(encoding="utf-8"),
                         t.control_guide(self.controls))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.examples = build_reports()
        self.report = deepcopy(self.examples["narrow-pass"])

    def rejected(self):
        with self.assertRaises(t.ValidationError):
            t.validate_report(self.report)

    def test_all_examples_valid_and_deterministic(self):
        self.assertEqual(self.examples, build_reports())
        for report in self.examples.values():
            t.validate_report(report)
            self.assertEqual(t.render_markdown(report), t.render_markdown(deepcopy(report)))

    def test_skeleton_is_unverified_and_valid(self):
        report = t.new_report("Test", "2026-10-09")
        t.validate_report(report)
        self.assertEqual({c["status"] for c in report["controls"]}, {"UNVERIFIED"})
        self.assertFalse(report["tests"])

    def test_registry_ids_cannot_be_missing_duplicate_or_reordered(self):
        for mutation in ("missing", "duplicate", "reordered"):
            self.report = deepcopy(self.examples["narrow-pass"])
            if mutation == "missing":
                self.report["controls"].pop()
            elif mutation == "duplicate":
                self.report["controls"][1]["id"] = "SEC-01"
            else:
                self.report["controls"].reverse()
            with self.subTest(mutation=mutation):
                self.rejected()

    def test_schema_rejects_unknown_fields_and_wrong_types(self):
        for mutate in (lambda r: r.update(extra="x"),
                       lambda r: r.update(synthetic="true"),
                       lambda r: r["tests"][0]["evidence"][0].update(line=True),
                       lambda r: r["tests"][0]["evidence"][0].update(line=0),
                       lambda r: r["project"].update(name=" "),
                       lambda r: r.update(toolkit_version="2.0.0")):
            self.report = deepcopy(self.examples["narrow-pass"])
            mutate(self.report)
            self.rejected()

    def test_invalid_calendar_dates_rejected(self):
        for value in ("2026-02-30", "09/10/2026", "20261009"):
            self.report["project"]["review_date"] = value
            with self.subTest(value=value):
                self.rejected()

    def test_unsupported_schema_keywords_and_refs_rejected(self):
        for schema in ({"type": "string", "not": {}}, {"format": "email"},
                       {"$ref": "https://example.invalid/schema"}, {"$ref": "#/$defs/missing"}):
            with self.subTest(schema=schema), self.assertRaises(t.ValidationError):
                t.validate_schema("test", schema)

    def test_pass_needs_evidence_and_passing_tests(self):
        for mutate in (lambda r: r["controls"][4].update(evidence=[]),
                       lambda r: r["controls"][4].update(test_refs=[]),
                       lambda r: r["tests"][0].update(result="NOT RUN"),
                       lambda r: r["tests"][0].update(result="FAIL"),
                       lambda r: r["tests"][0].update(evidence=[])):
            self.report = deepcopy(self.examples["narrow-pass"])
            mutate(self.report)
            self.rejected()

    def test_unknown_applicability_never_passes(self):
        self.report["controls"][4]["applicability"] = "UNKNOWN"
        self.rejected()

    def test_not_applicable_is_consistent(self):
        self.report["controls"][0]["applicability"] = "YES"
        self.rejected()

    def test_missing_evidence_cannot_become_ready(self):
        self.report["controls"][4]["status"] = "UNVERIFIED"
        self.rejected()

    def test_fail_needs_demonstrated_failure(self):
        self.report["controls"][4]["status"] = "FAIL"
        self.report["release_recommendation"]["decision"] = "HOLD"
        self.rejected()

    def test_potential_does_not_become_confirmed_or_pass(self):
        self.report = deepcopy(self.examples["mixed-findings"])
        self.report["controls"][17]["status"] = "PASS"
        self.rejected()

    def test_unresolved_confirmed_finding_keeps_control_failed(self):
        self.report = deepcopy(self.examples["mixed-findings"])
        self.report["controls"][4]["status"] = "UNVERIFIED"
        self.rejected()

    def test_false_positive_requires_explanation_and_dismissal(self):
        self.report = deepcopy(self.examples["mixed-findings"])
        finding = self.report["findings"][1]
        finding.update(classification="FALSE POSITIVE", resolution="DISMISSED",
                       rationale="No server consumes this synthetic configuration; hypothetical exposure is not established.")
        t.validate_report(self.report)
        finding["resolution"] = "OPEN"
        self.rejected()

    def test_fix_requires_before_failure_and_after_pass(self):
        for mutate in (lambda r: r["tests"][0].update(result="PASS"),
                       lambda r: r["tests"][1].update(result="NOT RUN"),
                       lambda r: r["fixes"][0].update(verification="UNVERIFIED"),
                       lambda r: r.update(fixes=[]),
                       lambda r: r["scope"].update(mode="audit-only")):
            self.report = deepcopy(self.examples["remediation"])
            mutate(self.report)
            self.rejected()

    def test_unverified_implementation_stays_open_and_failed(self):
        self.report = deepcopy(self.examples["remediation"])
        self.report["fixes"][0]["verification"] = "UNVERIFIED"
        self.report["findings"][0]["resolution"] = "OPEN"
        self.report["controls"][4].update(status="FAIL", test_refs=["T-001"])
        self.report["release_recommendation"]["decision"] = "REVIEW REQUIRED"
        t.validate_report(self.report)

    def test_cross_references_and_duplicate_ids_rejected(self):
        for mutate in (lambda r: r["controls"][4].update(test_refs=["T-999"]),
                       lambda r: r["tests"].append(deepcopy(r["tests"][0])),
                       lambda r: r["findings"].append(deepcopy(r["findings"][0])),
                       lambda r: r["fixes"][0].update(finding_id="F-999")):
            self.report = deepcopy(self.examples["remediation"])
            mutate(self.report)
            self.rejected()

    def test_identifier_cannot_smuggle_a_trailing_newline(self):
        self.report["tests"][0]["id"] += "\n"
        self.rejected()

    def test_paths_cannot_traverse_or_be_absolute(self):
        for path in ("../secret", "nested/../../secret", "/etc/passwd", "C:\\keys.txt", "C:keys.txt",
                     "\\\\server\\private", "https://example.invalid/x", "name\nforged"):
            self.report["tests"][0]["evidence"][0]["path"] = path
            with self.subTest(path=path):
                self.rejected()

    def test_missing_tool_cannot_claim_execution(self):
        self.report["tools"][0].update(availability="MISSING", execution="COMPLETED")
        self.rejected()

    def test_markdown_includes_contract_sections(self):
        rendered = t.render_markdown(self.examples["remediation"])
        for section in ("Technology stack", "Audit scope", "Threat model", "Control coverage", "Findings",
                        "Implemented fixes", "Test and review results", "Optional tools", "Remaining Risks",
                        "Limitations", "Release recommendation"):
            self.assertIn("## " + section, rendered)
        self.assertIn("SYNTHETIC EXAMPLE", rendered)
        self.assertIn("Before: T-001; after: T-002, T-003", rendered)

    def test_supplied_markup_is_escaped_in_both_formats(self):
        attack = '</pre><script>alert(1)</script>[open](https://example.invalid)\n# Forged'
        self.report["project"]["name"] = attack
        rendered = t.render_markdown(self.report)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("[open](https://example.invalid)", rendered)
        self.assertNotIn("\n# Forged", rendered)
        page = t.render_html(rendered)
        self.assertNotIn("<script>", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("<a ", page)


class RedactionTests(unittest.TestCase):
    def test_credential_assignments_and_headers(self):
        values = ["password=synthetic-value", 'api_key="synthetic value with spaces"',
                  "'client_secret': 'synthetic value'", "Authorization: Bearer synthetic.bearer.token",
                  "Authorization: Basic c3ludGhldGljOm9ubHk="]
        for value in values:
            with self.subTest(value=value):
                redacted = t.redact(value)
                self.assertIn("REDACTED", redacted)
                self.assertNotIn("synthetic-value", redacted)
                self.assertNotIn("synthetic value", redacted)

    def test_nested_values_urls_tokens_jwt_and_private_key(self):
        data = {"password": "opaque-value", "nested": [
            "postgres://fixture:synthetic-pass@localhost/db",
            "ghp_" + "x" * 36, "sk-proj-" + "x" * 32, "AKIA" + "X" * 16,
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.c3ludGhldGlj",
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC ONLY\n-----END PRIVATE KEY-----",
        ]}
        output = t.redact(data)
        self.assertEqual(output["password"], "[REDACTED]")
        self.assertTrue(all("REDACTED" in value for value in output["nested"]))
        self.assertEqual(data["password"], "opaque-value")

    def test_literal_redaction_is_deterministic_and_idempotent(self):
        data = {"description": "opaque-long-value and opaque-long"}
        first = t.redact(data, ["opaque-long", "opaque-long-value"])
        self.assertEqual(first, t.redact(data, ["opaque-long-value", "opaque-long"]))
        self.assertEqual(first, t.redact(first))
        self.assertEqual(first["description"], "[REDACTED] and [REDACTED]")

    def test_opaque_values_are_not_claimed_to_be_detectable(self):
        self.assertEqual(t.redact("opaque-business-value"), "opaque-business-value")

    def test_report_permission_narrative_survives_but_headers_are_masked(self):
        report = {"scope": {"authorization": "Approved local fixture review"},
                  "headers": {"authorization": "opaque-header-credential"}}
        result = t.redact(report)
        self.assertEqual(result["scope"]["authorization"], "Approved local fixture review")
        self.assertEqual(result["headers"]["authorization"], "[REDACTED]")
        report["scope"]["authorization"] = "Approved; password=synthetic-credential"
        self.assertNotIn("synthetic-credential", t.redact(report)["scope"]["authorization"])

    def test_empty_or_nonstring_literals_rejected(self):
        for literals in ([""], [False], [None]):
            with self.subTest(literals=literals), self.assertRaises(t.ValidationError):
                t.redact("text", literals)


class FilesystemAndCliTests(unittest.TestCase):
    def setUp(self):
        # All created test files remain under this explicitly selected repository.
        self.directory = tempfile.TemporaryDirectory(prefix="toolkit-test-", dir=t.ROOT)
        self.addCleanup(self.directory.cleanup)
        self.workspace = Path(self.directory.name).resolve()

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = t.main(list(args))
        return result, stdout.getvalue(), stderr.getvalue()

    def test_tool_lookup_never_claims_a_scan(self):
        which = Mock(return_value=None)
        result = t.tool_inventory(which)
        self.assertEqual(which.call_count, 3)
        self.assertEqual({item["availability"] for item in result}, {"MISSING"})
        self.assertEqual({item["execution"] for item in result}, {"NOT RUN"})
        available = t.tool_inventory(lambda _: "synthetic-path")
        self.assertEqual({item["availability"] for item in available}, {"AVAILABLE"})
        self.assertEqual({item["execution"] for item in available}, {"NOT RUN"})

    def test_duplicate_keys_invalid_json_and_constants_rejected(self):
        path = self.workspace / "input.json"
        for content in ('{"a": 1, "a": 2}', '{"number": NaN}', "not-json", "\ufffd"):
            path.write_text(content, encoding="utf-8")
            with self.subTest(content=content), self.assertRaises(t.ValidationError):
                t.read_json(path)

    def test_large_input_rejected(self):
        path = self.workspace / "large.json"
        path.write_bytes(b" " * (t.MAX_INPUT_BYTES + 1))
        with self.assertRaises(t.ValidationError):
            t.read_json(path)

    def test_input_outside_workspace_rejected(self):
        for path in ("../outside.json", str(t.ROOT / "VERSION")):
            with self.subTest(path=path), self.assertRaises(t.ValidationError):
                t.inside(self.workspace, path)

    def test_output_exclusive_and_preflight_prevents_partial_overwrite(self):
        t.write_private_outputs(self.workspace, {"existing.md": "original"})
        with self.assertRaises(t.ValidationError):
            t.write_private_outputs(self.workspace, {"new.md": "new", "existing.md": "replacement"})
        self.assertEqual((self.workspace / t.OUTPUT_DIR / "existing.md").read_text(), "original")
        self.assertFalse((self.workspace / t.OUTPUT_DIR / "new.md").exists())

    def test_output_names_are_bounded(self):
        for name in ("../escape.md", "/absolute.md", "nested/file.md", "UPPER.md", "x" * 100):
            with self.subTest(name=name), self.assertRaises(t.ValidationError):
                t.write_private_outputs(self.workspace, {name: "text"})

    def test_symlink_input_escape_and_output_directory_rejected(self):
        outside = self.workspace / "selected-other-root"
        outside.mkdir()
        selected = self.workspace / "selected"
        selected.mkdir()
        link = selected / t.OUTPUT_DIR
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("OS did not permit symlink creation; resolved-path checks are covered separately")
        with self.assertRaises(t.ValidationError):
            t.inside(selected, link / "file.json")
        with self.assertRaises(t.ValidationError):
            t.write_private_outputs(selected, {"report.md": "text"})
        self.assertFalse((outside / "report.md").exists())

    def test_new_and_report_end_to_end(self):
        args = ("--workspace", str(self.workspace))
        self.assertEqual(self.run_cli("new", *args, "--project-name", "Fixture", "--review-date", "2026-10-09")[0], 0)
        source = self.workspace / t.OUTPUT_DIR / "audit.json"
        original = source.read_bytes()
        result = self.run_cli("report", *args, "--input", f"{t.OUTPUT_DIR}/audit.json", "--html")
        self.assertEqual(result[0], 0, result[2])
        folder = self.workspace / t.OUTPUT_DIR
        for name in ("report.md", "report.redacted.json", "report.html"):
            self.assertTrue((folder / name).is_file())
        t.validate_report(t.read_json(folder / "report.redacted.json"))
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(self.run_cli("report", *args, "--input", f"{t.OUTPUT_DIR}/audit.json")[0], 2)

    def test_cli_redacts_all_outputs_without_rewriting_source(self):
        report = t.new_report("Fixture", "2026-10-09")
        report["remaining_risks"] = ["password=synthetic-credential", "opaque-sensitive-fixture"]
        source = self.workspace / "input.json"
        source.write_text(json.dumps(report), encoding="utf-8")
        literals = self.workspace / "redactions.json"
        literals.write_text('["opaque-sensitive-fixture"]', encoding="utf-8")
        result = self.run_cli("report", "--workspace", str(self.workspace), "--input", "input.json",
                              "--redact-file", "redactions.json", "--html")
        self.assertEqual(result[0], 0, result[2])
        for output in (self.workspace / t.OUTPUT_DIR).iterdir():
            contents = output.read_text(encoding="utf-8")
            self.assertNotIn("synthetic-credential", contents)
            self.assertNotIn("opaque-sensitive-fixture", contents)
        self.assertIn("synthetic-credential", source.read_text(encoding="utf-8"))

    def test_invalid_input_has_no_output_or_sensitive_diagnostic(self):
        source = self.workspace / "input.json"
        source.write_text('{"sensitive-fixture-value": true}', encoding="utf-8")
        result, stdout, stderr = self.run_cli("report", "--workspace", str(self.workspace), "--input", "input.json")
        self.assertEqual(result, 2)
        self.assertNotIn("sensitive-fixture-value", stdout + stderr)
        self.assertFalse((self.workspace / t.OUTPUT_DIR).exists())

    def test_broken_local_markdown_link_rejected(self):
        (self.workspace / "readme.md").write_text("[missing](missing.md)", encoding="utf-8")
        with self.assertRaises(t.ValidationError):
            t.validate_links(self.workspace)

    def test_local_heading_links_and_duplicate_slugs(self):
        (self.workspace / "readme.md").write_text(
            "# Local heading\n[here](#local-heading)\n[other](guide.md#fix-verify-1)\n"
            "[encoded](guide.md#caf%C3%A9)\n", encoding="utf-8")
        (self.workspace / "guide.md").write_text(
            "## Fix. `Verify`.\n## Fix. `Verify`.\n## Café\n", encoding="utf-8")
        self.assertEqual(t.validate_links(self.workspace), 3)

    def test_missing_same_file_or_cross_file_heading_rejected(self):
        (self.workspace / "guide.md").write_text("# Existing\n", encoding="utf-8")
        for target in ("#missing", "guide.md#missing"):
            (self.workspace / "readme.md").write_text(f"# Existing\n[bad]({target})\n", encoding="utf-8")
            with self.subTest(target=target), self.assertRaises(t.ValidationError):
                t.validate_links(self.workspace)

    def test_fenced_example_links_and_headings_are_ignored(self):
        for marker in ("```", "~~~~"):
            (self.workspace / "readme.md").write_text(
                f"# Real\n{marker}md\n# Fake\n[bad](missing.md)\n{marker}\n[ok](#real)\n",
                encoding="utf-8")
            with self.subTest(marker=marker):
                self.assertEqual(t.validate_links(self.workspace), 1)
                self.assertNotIn("fake", t.markdown_anchors((self.workspace / "readme.md").read_text()))

    def test_markdown_link_cannot_escape_workspace(self):
        (self.workspace / "readme.md").write_text("[outside](../README.md)\n", encoding="utf-8")
        with self.assertRaises(t.ValidationError):
            t.validate_links(self.workspace)

    def test_posix_private_creation_modes_when_available(self):
        if os.name == "posix":
            t.write_private_outputs(self.workspace, {"report.md": "private"})
            self.assertEqual((self.workspace / t.OUTPUT_DIR).stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.workspace / t.OUTPUT_DIR / "report.md").stat().st_mode & 0o777, 0o600)
        else:
            # Do not falsely claim mode bits enforce a Windows ACL.
            self.assertEqual(os.name, "nt")


class PromptConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.universal = "# Universal prompt\n\n```text\nAudit the selected application.\n```\n"
        self.readme = ("# AppSec Review Kit\n\nIntroduction.\n\n## Copy Security Audit Prompt\n\n"
                       "```text\nAudit the selected application.\n```\n\n## Usage\n\nInstructions.\n\n"
                       "## Copy-and-Paste Security Audit Prompt\n\n"
                       "```text\nAudit the selected application.\n```\n")

    def test_matching_prompt_copies_are_accepted(self):
        t.validate_prompt_copies(self.readme, self.universal)

    def test_unrelated_text_code_blocks_are_preserved(self):
        readme = self.readme.replace("Instructions.\n", "Instructions.\n\n```text\nproject/\n  README.md\n```\n")
        t.validate_prompt_copies(readme, self.universal)

    def test_drift_in_either_readme_copy_is_rejected(self):
        for index in (0, 1):
            parts = self.readme.split("Audit the selected application.")
            parts[index] += "Changed prompt."
            changed = "Audit the selected application.".join(parts)
            with self.subTest(copy=index), self.assertRaises(t.ValidationError):
                t.validate_prompt_copies(changed, self.universal)

    def test_canonical_change_requires_updating_both_copies(self):
        changed = self.universal.replace("Audit the selected application.", "Review the selected scope.")
        with self.assertRaises(t.ValidationError):
            t.validate_prompt_copies(self.readme, changed)
        t.validate_prompt_copies(
            self.readme.replace("Audit the selected application.", "Review the selected scope."), changed)

    def test_missing_or_extra_copy_is_rejected(self):
        block = "```text\nAudit the selected application.\n```\n"
        for changed in (self.readme.replace(block, "", 1), self.readme + block):
            with self.subTest(extra=changed.endswith(block + block)), self.assertRaises(t.ValidationError):
                t.validate_prompt_copies(changed, self.universal)

    def test_copy_sections_must_be_first_and_last(self):
        for changed in (self.readme.replace("## Copy Security Audit Prompt", "## Other", 1),
                        self.readme + "\n## Appendix\n", self.readme + "\nTrailing content.\n",
                        self.readme.replace("## Copy Security Audit Prompt", "## Before\n\n## Copy Security Audit Prompt")):
            with self.subTest(readme=changed), self.assertRaises(t.ValidationError):
                t.validate_prompt_copies(changed, self.universal)

    def test_empty_or_duplicate_canonical_blocks_are_rejected(self):
        for changed in (self.universal.replace("Audit the selected application.", ""),
                        self.universal + "\n```text\nAnother prompt.\n```\n"):
            with self.subTest(universal=changed), self.assertRaises(t.ValidationError):
                t.validate_prompt_copies(self.readme, changed)


class RepositoryIntegrationTests(unittest.TestCase):
    def test_public_repository_validation(self):
        self.assertIn("Validated 30 controls, 3 synthetic reports", t.validate_repository())

    def test_universal_prompt_matches_readme(self):
        readme = (t.ROOT / "README.md").read_text(encoding="utf-8")
        prompt = (t.ROOT / "prompts" / "universal.md").read_text(encoding="utf-8")
        t.validate_prompt_copies(readme, prompt)
        block = prompt.split("```text\n", 1)[1].split("```", 1)[0]
        self.assertEqual(readme.count("```text\n" + block + "```"), 2)
        self.assertTrue(readme.rstrip().endswith("```text\n" + block + "```"))
        self.assertEqual(readme.rsplit("\n## ", 1)[-1].splitlines()[0],
                         "Copy-and-Paste Security Audit Prompt")

    def test_readme_coverage_uses_canonical_control_names(self):
        readme = (t.ROOT / "README.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\|[^|]*\| (SEC-\d{2}) \| ([^|]+) \|$", readme, re.M)
        self.assertEqual(len(rows), 30)
        self.assertEqual(dict(rows), {c["id"]: c["name"] for c in t.load_controls()})

    def test_public_examples_match_current_behavioral_model(self):
        for stem, report in build_reports().items():
            self.assertEqual(t.read_json(t.ROOT / "examples" / "reports" / (stem + ".json")), report)

    def test_fixture_applicability_is_not_inferred_from_reviewer(self):
        report = build_reports()["mixed-findings"]
        for number in (1, 4, 14, 30):
            self.assertEqual(report["controls"][number - 1]["status"], "NOT APPLICABLE")
        self.assertEqual(report["controls"][4]["status"], "FAIL")
        self.assertEqual(report["controls"][17]["status"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
