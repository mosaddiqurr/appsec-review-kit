#!/usr/bin/env python3
"""Local report utilities. No network, subprocesses, or vulnerability detection."""

import argparse
from collections import Counter
from datetime import date
import html
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sys
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
CONTROL_IDS = tuple(f"SEC-{i:02d}" for i in range(1, 31))
MAX_INPUT_BYTES = 5 * 1024 * 1024
OUTPUT_DIR = ".security-reports"


class ValidationError(ValueError):
    """An invalid document; messages deliberately omit supplied values."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def read_json(path):
    """Bound input size; reject duplicate keys and nonstandard numeric constants."""
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "JSON contains duplicate object keys")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValidationError("JSON contains a nonstandard numeric constant")

    with Path(path).open("rb") as handle:
        data = handle.read(MAX_INPUT_BYTES + 1)
    require(len(data) <= MAX_INPUT_BYTES, "JSON exceeds the 5 MiB input limit")
    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs,
                          parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValidationError("Invalid UTF-8 JSON document") from exc


def load_controls(path=None):
    controls = read_json(path or inside(ROOT, "checks/controls.json"))
    validate_controls(controls)
    return controls


def validate_controls(controls):
    require(isinstance(controls, list) and len(controls) == 30,
            "Registry must contain exactly 30 controls")
    keys = {"id", "name", "objective", "technology", "applicability",
            "failure_patterns", "detection", "tools", "remediation",
            "verification", "severity", "references", "automation_limits"}
    seen = set()
    names = set()
    for index, control in enumerate(controls):
        where = f"control[{index}]"
        require(isinstance(control, dict) and set(control) == keys,
                f"{where}: invalid fields")
        require(control["id"] == CONTROL_IDS[index] and control["id"] not in seen,
                f"{where}: missing, duplicate, or unordered ID")
        seen.add(control["id"])
        for key in ("name", "objective", "severity", "automation_limits"):
            require(isinstance(control[key], str) and bool(control[key].strip()),
                    f"{where}.{key}: expected nonempty text")
        require(control["name"] not in names, f"{where}: duplicate name")
        names.add(control["name"])
        for key in ("technology", "failure_patterns", "detection", "tools",
                    "remediation", "verification"):
            value = control[key]
            require(isinstance(value, list) and len(value) >= 1 and
                    all(isinstance(v, str) and v.strip() for v in value),
                    f"{where}.{key}: expected nonempty text array")
        applicability = control["applicability"]
        require(isinstance(applicability, dict) and
                set(applicability) == {"when", "not_applicable_when"} and
                all(isinstance(v, str) and v.strip() for v in applicability.values()),
                f"{where}: invalid applicability metadata")
        refs = control["references"]
        require(isinstance(refs, list) and bool(refs), f"{where}: missing references")
        for ref in refs:
            require(isinstance(ref, dict) and set(ref) == {"title", "url"} and
                    all(isinstance(v, str) and v.strip() for v in ref.values()),
                    f"{where}: invalid reference")
            parsed = urlparse(ref["url"])
            require(parsed.scheme == "https" and parsed.hostname in {
                "cwe.mitre.org", "cheatsheetseries.owasp.org", "owasp.org",
                "www.postgresql.org", "www.rfc-editor.org"},
                f"{where}: reference must use an approved official HTTPS source")


# This deliberately implements only the JSON Schema keywords used by our checked-in
# schema. Unknown keywords fail closed; this is not a general JSON Schema library.
SCHEMA_KEYS = {"$schema", "$id", "title", "description", "$defs", "$ref",
               "type", "const", "enum", "properties", "required",
               "additionalProperties", "items", "minItems", "maxItems",
               "uniqueItems", "minLength", "pattern", "format", "minimum"}


def check_schema(schema):
    require(isinstance(schema, dict) and set(schema) <= SCHEMA_KEYS,
            "Unsupported JSON Schema keyword")
    if "type" in schema:
        require(schema["type"] in {"object", "array", "string", "integer", "boolean"},
                "Unsupported JSON Schema type")
    if "format" in schema:
        require(schema["format"] == "date", "Unsupported JSON Schema format")
    if "$ref" in schema:
        require(schema["$ref"].startswith("#/$defs/"), "Only local schema references supported")
    for container in ("properties", "$defs"):
        for child in schema.get(container, {}).values():
            check_schema(child)
    if "items" in schema:
        check_schema(schema["items"])


def validate_schema(value, schema, root=None, where="report"):
    if root is None:
        check_schema(schema)
        root = schema
    if "$ref" in schema:
        name = schema["$ref"].removeprefix("#/$defs/")
        require(name in root.get("$defs", {}), "Undefined local schema reference")
        validate_schema(value, root["$defs"][name], root, where)
    kind = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    if kind:
        require(type(value) is types[kind], f"{where}: wrong JSON type")
    if "const" in schema:
        require(type(value) is type(schema["const"]) and value == schema["const"],
                f"{where}: unsupported constant")
    if "enum" in schema:
        require(value in schema["enum"], f"{where}: invalid enum value")
    if kind == "object":
        require(set(schema.get("required", [])) <= set(value), f"{where}: missing required field")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            require(set(value) <= set(properties), f"{where}: unexpected field")
        for key, child in properties.items():
            if key in value:
                validate_schema(value[key], child, root, f"{where}.{key}")
    elif kind == "array":
        require(len(value) >= schema.get("minItems", 0), f"{where}: too few items")
        require(len(value) <= schema.get("maxItems", len(value)), f"{where}: too many items")
        if schema.get("uniqueItems"):
            serialized = [json.dumps(v, sort_keys=True) for v in value]
            require(len(serialized) == len(set(serialized)), f"{where}: duplicate items")
        for i, child in enumerate(value):
            validate_schema(child, schema["items"], root, f"{where}[{i}]")
    elif kind == "string":
        require(len(value.strip()) >= schema.get("minLength", 0), f"{where}: empty text")
        if "pattern" in schema:
            require(re.search(schema["pattern"], value) is not None,
                    f"{where}: text does not match required pattern")
        if schema.get("format") == "date":
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise ValidationError(f"{where}: invalid calendar date") from exc
    elif kind == "integer" and "minimum" in schema:
        require(value >= schema["minimum"], f"{where}: integer below minimum")


def relative_evidence_path(path):
    """Portable target-relative paths only, with no traversal, drives, or URLs."""
    posix = PurePosixPath(path.replace("\\", "/"))
    windows = PureWindowsPath(path)
    return (bool(path.strip()) and not posix.is_absolute() and not windows.drive and
            ".." not in posix.parts and ":" not in path and
            not any(ord(char) < 32 for char in path))


def validate_report(report, schema=None):
    validate_schema(report, schema or read_json(inside(ROOT, "templates/report.schema.json")))
    controls = report["controls"]
    require([c["id"] for c in controls] == list(CONTROL_IDS),
            "Report must cover all 30 IDs exactly once, in order")
    tests = {t["id"]: t for t in report["tests"]}
    findings = {f["id"]: f for f in report["findings"]}
    require(all(re.fullmatch(r"T-[0-9]{3}", identifier) for identifier in tests), "Invalid test ID")
    require(all(re.fullmatch(r"F-[0-9]{3}", identifier) for identifier in findings), "Invalid finding ID")
    require(len(tests) == len(report["tests"]), "Duplicate test IDs")
    require(len(findings) == len(report["findings"]), "Duplicate finding IDs")
    fixes = {f["finding_id"]: f for f in report["fixes"]}
    require(len(fixes) == len(report["fixes"]), "Duplicate fix records")
    if report["scope"]["mode"] == "audit-only":
        require(not fixes, "Audit-only reports cannot contain implemented fixes")
    for test in tests.values():
        if test["result"] != "NOT RUN":
            require(bool(test["evidence"]), "Executed tests/reviews need evidence")
    for control in controls:
        refs = control["test_refs"]
        require(set(refs) <= set(tests), "Control references an unknown test")
        status, applies = control["status"], control["applicability"]
        require((status == "NOT APPLICABLE") == (applies == "NO"),
                "NOT APPLICABLE requires applicability NO, and vice versa")
        if applies == "UNKNOWN":
            require(status == "UNVERIFIED", "Unknown applicability must remain UNVERIFIED")
        if status in {"PASS", "FAIL"}:
            require(applies == "YES" and bool(control["evidence"]),
                    "PASS/FAIL requires applicability YES and evidence")
        if status == "PASS":
            require(bool(refs) and all(tests[r]["result"] == "PASS" for r in refs),
                    "PASS needs referenced passing tests/reviews with no unexecuted tests")
        if status == "FAIL":
            demonstrated = any(tests[r]["result"] == "FAIL" for r in refs) or any(
                f["control_id"] == control["id"] and f["classification"] == "CONFIRMED"
                and f["resolution"] in {"OPEN", "ACCEPTED RISK"} for f in findings.values())
            require(demonstrated, "FAIL needs a failed test/review or unresolved confirmed finding")
    for finding in findings.values():
        control = controls[CONTROL_IDS.index(finding["control_id"])]
        classification, resolution = finding["classification"], finding["resolution"]
        require(control["applicability"] != "NO", "Finding linked to a non-applicable control")
        require((classification == "FALSE POSITIVE") == (resolution == "DISMISSED"),
                "False positives must be DISMISSED, and only false positives can be dismissed")
        if classification == "POTENTIAL":
            require(resolution == "OPEN" and control["status"] in {"UNVERIFIED", "FAIL"},
                    "Potential findings remain OPEN under UNVERIFIED or FAIL controls")
        if classification == "CONFIRMED" and resolution in {"OPEN", "ACCEPTED RISK"}:
            require(control["status"] == "FAIL", "Unresolved confirmed findings require FAIL")
        if resolution == "FIXED":
            require(classification == "CONFIRMED" and finding["id"] in fixes and
                    fixes[finding["id"]]["verification"] == "VERIFIED",
                    "FIXED needs a confirmed finding and verified fix record")
    for fix in fixes.values():
        require(fix["finding_id"] in findings, "Fix references an unknown finding")
        finding = findings[fix["finding_id"]]
        require(finding["classification"] == "CONFIRMED", "Fixes need confirmed findings")
        before, after = fix["before_test_refs"], fix["after_test_refs"]
        require(set(before + after) <= set(tests), "Fix references an unknown test")
        if fix["verification"] == "VERIFIED":
            require(finding["resolution"] == "FIXED" and
                    any(tests[r]["result"] == "FAIL" for r in before) and
                    all(tests[r]["result"] == "PASS" for r in after),
                    "Verified fixes need failing before and passing after evidence")
        else:
            require(finding["resolution"] != "FIXED", "Unverified fixes cannot be FIXED")
        require(all(relative_evidence_path(p) for p in fix["changed_files"]),
                "Changed-file paths must be relative to the target")
    for section in (controls, list(findings.values()), list(tests.values())):
        for item in section:
            for evidence in item["evidence"]:
                require(relative_evidence_path(evidence["path"]),
                        "Evidence paths must be relative to the target")
    for tool in report["tools"]:
        if tool["availability"] != "AVAILABLE":
            require(tool["execution"] == "NOT RUN", "Unavailable tools cannot have executed")
    if report["release_recommendation"]["decision"] == "READY WITHIN SCOPE":
        require(all(c["status"] in {"PASS", "NOT APPLICABLE"} for c in controls),
                "Readiness requires verified applicable controls within the stated scope")
        require(not any(f["resolution"] in {"OPEN", "ACCEPTED RISK"} for f in findings.values()),
                "Readiness cannot include unresolved findings")


SENSITIVE_KEY = re.compile(r"(?i)(?:password|passwd|secret|client[_-]?secret|api[_-]?key|token|access[_-]?token|"
                           r"refresh[_-]?token|private[_-]?key|authorization)")
REDACTION_PATTERNS = [
    (re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?"
                r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/_=.-]+"), "[REDACTED AUTHORIZATION]"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED KEY]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
                r"sk-(?:proj-)?[A-Za-z0-9_-]{16,})\b"), "[REDACTED TOKEN]"),
    (re.compile(r'''(?ix)(["']?\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|
                refresh[_-]?token|client[_-]?secret)["']?\s*[:=]\s*)
                (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)'''), r"\1[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED JWT]"),
]


def redact(value, literals=()):
    """Best-effort output redaction, not a secret scanner or privacy guarantee."""
    require(all(isinstance(v, str) and v for v in literals), "Redaction literals must be nonempty strings")
    ordered = sorted(set(literals), key=lambda v: (-len(v), v))

    def walk(item, trail=()):
        if isinstance(item, dict):
            # The schema's scope.authorization is a permission narrative, not an
            # HTTP Authorization header. Still apply textual masks to its value.
            return {key: "[REDACTED]" if SENSITIVE_KEY.fullmatch(key) and
                    not (trail == ("scope",) and key == "authorization")
                    else walk(child, trail + (key,))
                    for key, child in item.items()}
        if isinstance(item, list):
            return [walk(child, trail) for child in item]
        if isinstance(item, str):
            for literal in ordered:
                item = item.replace(literal, "[REDACTED]")
            for pattern, replacement in REDACTION_PATTERNS:
                item = pattern.sub(replacement, item)
        return item
    return walk(value)


def markdown_text(value):
    value = html.escape(str(value), quote=False)
    value = re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", value)
    return value.replace("\r", " ").replace("\n", " ")


def render_markdown(report):
    """Render every contractual section; caller validates and redacts first."""
    text = markdown_text
    lines = ["# Security review", "", "SYNTHETIC EXAMPLE" if report["synthetic"] else "PRIVATE LOCAL REPORT",
             "", f"Project: {text(report['project']['name'])}",
             f"Review date: {text(report['project']['review_date'])}",
             f"Revision: {text(report['project']['revision'])}",
             f"Toolkit: {VERSION}; schema: 1",
             f"Toolkit revision: {text(report['toolkit_revision'])}", "", "## Technology stack", ""]

    def bullets(values):
        lines.extend([f"- {text(v)}" for v in values] or ["- None recorded."])
        lines.append("")

    def evidence(values):
        bullets([f"{e['path']}:{e['line']} — {e['description']}" for e in values])

    bullets(report["project"]["stack"])
    scope = report["scope"]
    lines.extend(["## Audit scope", "", f"Target: {text(scope['target'])}",
                  f"Mode: {text(scope['mode'])}", f"Authorization: {text(scope['authorization'])}",
                  "", "Included:", ""])
    bullets(scope["included"])
    lines.extend(["Excluded:", ""])
    bullets(scope["excluded"])
    lines.extend(["## Threat model", ""])
    for key, values in scope["threat_model"].items():
        lines.extend([f"### {key.replace('_', ' ').title()}", ""])
        bullets(values)
    counts = Counter(c["status"] for c in report["controls"])
    lines.extend(["## Control coverage", "", " | ".join(
        f"{status}: {counts[status]}" for status in ("PASS", "FAIL", "NOT APPLICABLE", "UNVERIFIED")),
        "", "PASS applies only to the recorded requirement and evidence scope.", ""])
    for control in report["controls"]:
        lines.extend([f"### {control['id']} — {control['status']}", "",
                      f"Applicability: {control['applicability']}",
                      f"Requirement: {text(control['requirement'])}",
                      f"Rationale: {text(control['reason'])}",
                      f"Tests/reviews: {', '.join(control['test_refs']) or 'None'}", ""])
        evidence(control["evidence"])
    lines.extend(["## Findings", ""])
    if not report["findings"]:
        lines.extend(["No confirmed or potential findings recorded within the stated scope.", ""])
    for finding in report["findings"]:
        lines.extend([f"### {finding['id']}: {text(finding['title'])}", "",
                      f"{finding['classification']} | {finding['severity']} | {finding['resolution']} | {finding['control_id']}",
                      f"Impact: {text(finding['impact'])}",
                      f"Classification rationale: {text(finding['rationale'])}",
                      f"Remediation: {text(finding['remediation'])}", ""])
        evidence(finding["evidence"])
    lines.extend(["## Implemented fixes", ""])
    if not report["fixes"]:
        lines.extend(["None.", ""])
    for fix in report["fixes"]:
        lines.extend([f"### {fix['finding_id']} — {fix['verification']}", "", text(fix["summary"]), "",
                      f"Before: {', '.join(fix['before_test_refs'])}; after: {', '.join(fix['after_test_refs'])}", ""])
        bullets(fix["changed_files"])
    lines.extend(["## Test and review results", ""])
    if not report["tests"]:
        lines.extend(["No tests or reviews recorded.", ""])
    for test in report["tests"]:
        lines.extend([f"### {test['id']}: {text(test['name'])}", "",
                      f"{test['method']} | {test['result']}", text(test["details"]), ""])
        evidence(test["evidence"])
    lines.extend(["## Optional tools", ""])
    bullets([f"{t['name']}: {t['availability']}; {t['execution']}; version {t['version']}; {t['details']}"
             for t in report["tools"]])
    for key in ("remaining_risks", "limitations"):
        lines.extend([f"## {key.replace('_', ' ').title()}", ""])
        bullets(report[key])
    recommendation = report["release_recommendation"]
    lines.extend(["## Release recommendation", "", recommendation["decision"], "",
                  text(recommendation["rationale"]), "",
                  "This report is a bounded assessment, not a security guarantee or certification.", ""])
    return "\n".join(lines)


def render_html(markdown):
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
            'base-uri \'none\'; form-action \'none\'">'
            '<title>Local security review</title></head><body><main>'
            '<h1>Local security review</h1><pre>' + html.escape(markdown) +
            '</pre></main></body></html>\n')


def tool_inventory(which=None):
    which = which or shutil.which
    return [{"name": name, "availability": "AVAILABLE" if which(name) else "MISSING",
             "execution": "NOT RUN", "version": "Not inspected",
             "details": "PATH lookup only; no executable was run."}
            for name in ("semgrep", "gitleaks", "osv-scanner")]


def new_report(name, review_date, controls=None):
    return {
        "schema_version": "1", "toolkit_version": VERSION, "toolkit_revision": "Not recorded", "synthetic": False,
        "project": {"name": name, "review_date": review_date, "revision": "Not recorded",
                    "stack": ["Not inspected"]},
        "scope": {"target": ".", "mode": "audit-only", "authorization": "Not recorded; no review has run",
                  "included": ["Scope must be selected before review"], "excluded": [],
                  "threat_model": {"assets": ["Not identified"], "entry_points": ["Not identified"],
                                   "trust_boundaries": ["Not identified"], "abuse_cases": ["Not identified"]}},
        "controls": [{"id": c["id"], "applicability": "UNKNOWN", "status": "UNVERIFIED",
                      "requirement": c["objective"], "reason": "Not reviewed; applicability is unknown",
                      "evidence": [], "test_refs": []} for c in (controls or load_controls())],
        "findings": [], "fixes": [], "tests": [], "tools": [], "remaining_risks": ["Review not started"],
        "limitations": ["An empty report is not evidence that the application is secure."],
        "release_recommendation": {"decision": "REVIEW REQUIRED", "rationale": "Review not started"},
    }


def inside(workspace, value):
    path = Path(value)
    candidate = (path if path.is_absolute() else workspace / path).resolve()
    require(candidate.is_relative_to(workspace), "Path escapes the selected workspace")
    return candidate


def write_private_outputs(workspace, files):
    """Fixed output directory; refuse traversal, symlink escape, and overwrite."""
    require(all(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,79}", name) and ".." not in name
                for name in files), "Invalid output filename")
    folder = workspace / OUTPUT_DIR
    require(not folder.is_symlink(), "Output directory cannot be a symlink")
    inside(workspace, folder)
    folder.mkdir(mode=0o700, exist_ok=True)
    require(folder.is_dir(), "Output location is not a directory")
    require(all(not (folder / name).exists() and not (folder / name).is_symlink()
                for name in files), "Output already exists; choose a different stem")
    for name, content in files.items():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(folder / name, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)


def control_guide(controls):
    lines = ["# Security control guide", "",
             "30 review areas, not 30 presumed vulnerabilities. Select applicability from the target architecture.", "",
             "Generated from [controls.json](controls.json). Edit that registry, then run `python scripts/toolkit.py render-checks` from the toolkit root.", "",
             "Use with [the workflow](../docs/workflow.md) and [reporting contract](../docs/reporting.md).", ""]
    for c in controls:
        lines.extend([f"## {c['id']}: {c['name']}", "", f"**Objective:** {c['objective']}", "",
                      f"**Technology/architecture:** {', '.join(c['technology'])}", "",
                      f"**Applies when:** {c['applicability']['when']}", "",
                      f"**Not applicable when:** {c['applicability']['not_applicable_when']}", ""])
        for key in ("failure_patterns", "detection", "tools", "remediation", "verification"):
            lines.extend([f"**{key.replace('_', ' ').title()}:**", ""])
            lines.extend(f"- {v}" for v in c[key])
            lines.append("")
        lines.extend([f"**Severity considerations:** {c['severity']}", "",
                      f"**Automation limitations:** {c['automation_limits']}", "", "**References:**", ""])
        lines.extend(f"- [{r['title']}]({r['url']})" for r in c["references"])
        lines.append("")
    return "\n".join(lines)


def markdown_without_fences(contents):
    """Exclude fenced examples from link and heading checks."""
    lines = []
    fence = None
    for line in contents.splitlines():
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
        elif match:
            fence = match[1]
        else:
            lines.append(line)
    return "\n".join(lines)


def markdown_anchors(contents):
    """GitHub-style IDs for the ATX headings used in this repository."""
    anchors = set()
    for heading in re.findall(r"^ {0,3}#{1,6}[ \t]+(.+)$", markdown_without_fences(contents), re.M):
        heading = re.sub(r"[ \t]+#+[ \t]*$", "", heading).strip()
        heading = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", heading)
        heading = html.unescape(re.sub(r"<[^>]*>", "", heading))
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        candidate, suffix = slug, 0
        while candidate in anchors:
            suffix += 1
            candidate = f"{slug}-{suffix}"
        anchors.add(candidate)
    return anchors


def validate_links(root=ROOT):
    """Check local inline Markdown file targets and ATX heading fragments offline."""
    root = root.resolve()
    checked = 0
    for path in root.rglob("*.md"):
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        source = inside(root, path)
        contents = markdown_without_fences(source.read_text(encoding="utf-8"))
        for target in re.findall(r"!?\[[^\]]+\]\(([^)]+)\)", contents):
            target = target.strip().strip("<>")
            if urlparse(target).scheme:
                continue
            file_part, _, fragment = target.partition("#")
            resolved = (path.parent / unquote(file_part)).resolve() if file_part else source
            require(resolved.is_relative_to(root) and resolved.exists(),
                    f"Broken/out-of-scope local Markdown link in {path.relative_to(root)}")
            if fragment:
                require(resolved.is_file() and resolved.suffix.lower() == ".md" and
                        unquote(fragment) in markdown_anchors(resolved.read_text(encoding="utf-8")),
                        f"Broken local Markdown heading link in {path.relative_to(root)}")
            checked += 1
    return checked


def validate_prompt_copies(readme, universal):
    """Keep both README copy controls synchronized with the canonical prompt."""
    pattern = r"^```text\n(.*?)^```[ \t]*$"
    canonical = re.findall(pattern, universal, re.M | re.S)
    copies = re.findall(pattern, readme, re.M | re.S)
    require(len(canonical) == 1 and bool(canonical[0].strip()),
            "Universal prompt must contain one nonempty copyable text block")
    require(sum(block == canonical[0] for block in copies) == 2,
            "Both README prompt copies must exactly match prompts/universal.md")
    sections = re.split(r"^## ", markdown_without_fences(readme), flags=re.M)[1:]
    require(bool(sections) and sections[0].startswith("Copy Security Audit Prompt\n") and
            sections[-1].startswith("Copy-and-Paste Security Audit Prompt\n") and
            readme.count("## Copy Security Audit Prompt\n") == 1 and
            readme.count("## Copy-and-Paste Security Audit Prompt\n") == 1,
            "Prompt copy sections must follow the introduction and end the README")
    for heading in ("Copy Security Audit Prompt", "Copy-and-Paste Security Audit Prompt"):
        section = readme.split("## " + heading + "\n", 1)[1].split("\n## ", 1)[0]
        require(re.findall(pattern, section, re.M | re.S) == canonical,
                "Each prompt section must contain the complete canonical block")
    require(readme.rstrip().endswith("```text\n" + canonical[0] + "```"),
            "README must end with the complete universal prompt")


def validate_repository():
    controls = load_controls()
    require(inside(ROOT, "VERSION").read_text(encoding="utf-8").strip() == VERSION, "Version mismatch")
    require(inside(ROOT, "checks/README.md").read_text(encoding="utf-8") == control_guide(controls),
            "Control guide is stale; run render-checks")
    schema = read_json(inside(ROOT, "templates/report.schema.json"))
    check_schema(schema)
    examples = list(inside(ROOT, "examples/reports").glob("*.json"))
    require(len(examples) == 3, "Expected exactly three synthetic example reports")
    for path in examples:
        report = read_json(inside(ROOT, path))
        validate_report(report, schema)
        require(report["synthetic"], "Public examples must be marked synthetic")
        require(report == redact(report), "Example contains an unredacted sensitive pattern")
        require(inside(ROOT, path.with_suffix(".md")).read_text(encoding="utf-8") == render_markdown(report),
                "Example Markdown is stale")
        target = ROOT / "examples" / "fixtures"
        for section in (report["controls"], report["findings"], report["tests"]):
            for item in section:
                for evidence in item["evidence"]:
                    source = inside(target, evidence["path"])
                    require(source.is_file(), "Synthetic evidence file is missing")
                    require(evidence["line"] <= len(source.read_text(encoding="utf-8").splitlines()),
                            "Synthetic evidence line exceeds file length")
    links = validate_links()
    readme = inside(ROOT, "README.md").read_text(encoding="utf-8")
    universal = inside(ROOT, "prompts/universal.md").read_text(encoding="utf-8")
    validate_prompt_copies(readme, universal)
    return f"Validated 30 controls, 3 synthetic reports, generated Markdown, and {links} local links."


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="Validate this toolkit repository offline")
    commands.add_parser("tools", help="PATH lookup only; never executes scanners")
    commands.add_parser("render-checks", help="Regenerate the toolkit's public control guide")
    new = commands.add_parser("new", help="Create an UNVERIFIED private report skeleton")
    new.add_argument("--workspace", required=True)
    new.add_argument("--project-name", required=True)
    new.add_argument("--review-date", default=date.today().isoformat())
    new.add_argument("--stem", default="audit")
    report = commands.add_parser("report", help="Validate, redact, and render a local report")
    report.add_argument("--workspace", required=True)
    report.add_argument("--input", required=True)
    report.add_argument("--stem", default="report")
    report.add_argument("--redact-file", help="Workspace-local JSON array of literal values to mask")
    report.add_argument("--html", action="store_true", help="Also write an escaped standalone HTML view")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            print(validate_repository())
        elif args.command == "tools":
            print(json.dumps(tool_inventory(), indent=2))
        elif args.command == "render-checks":
            path = ROOT / "checks" / "README.md"
            require(not path.is_symlink(), "Control guide cannot be a symlink")
            inside(ROOT, path)
            path.write_text(control_guide(load_controls()), encoding="utf-8", newline="\n")
            print("Regenerated checks/README.md")
        else:
            workspace = Path(args.workspace).resolve(strict=True)
            require(workspace.is_dir(), "Workspace must be a directory")
            require(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", args.stem) is not None,
                    "Stem must contain only lowercase letters, numbers, underscores, or hyphens")
            literals = []
            if args.command == "new":
                data = new_report(args.project_name, args.review_date)
            else:
                data = read_json(inside(workspace, args.input))
                if args.redact_file:
                    literals = read_json(inside(workspace, args.redact_file))
                    require(isinstance(literals, list), "Redaction file must contain a JSON array")
            validate_report(data)
            sanitized = redact(data, literals)
            validate_report(sanitized)
            files = {args.stem + (".json" if args.command == "new" else ".redacted.json"):
                     json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n"}
            if args.command == "report":
                markdown = render_markdown(sanitized)
                files[args.stem + ".md"] = markdown
                if args.html:
                    files[args.stem + ".html"] = render_html(markdown)
            write_private_outputs(workspace, files)
            print(f"Wrote {len(files)} file(s) under the selected workspace's {OUTPUT_DIR}/")
        return 0
    except (ValidationError, OSError, RecursionError, ValueError):
        # No raw exception contents: file paths, keys, and parser context may be sensitive.
        print("Validation or local I/O failed. Check the schema, evidence, paths, and existing output names; no input values are echoed.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
