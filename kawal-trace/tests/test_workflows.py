"""CI workflow files must at least be valid YAML: GitHub reports a broken one only after it has been pushed."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))


def test_there_are_workflow_files():
    assert {path.name for path in WORKFLOWS} >= {"build.yml", "audit.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_unquoted_names_contain_no_colon_space(path):
    """The classic mistake: `name: Audit foo: bar` is a YAML syntax error (works without PyYAML installed)."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.match(r"^\s*(?:-\s+)?name:\s+(?P<value>.+?)\s*$", line)
        if not match:
            continue
        value = match.group("value")
        if value[0] in "\"'":
            continue
        assert ": " not in value and not value.endswith(":"), f"{path.name}:{number} unquoted name contains ': ' -> {value!r}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_parses_and_has_least_privilege(path):
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict) and "jobs" in document
    assert document.get("permissions") == {"contents": "read"}, "workflows must not get write access by default"
    for name, job in document["jobs"].items():
        assert "steps" in job, name
        assert "timeout-minutes" in job, f"{name} needs a timeout"


def test_audit_runs_on_a_schedule_and_pins_its_tool():
    text = (WORKFLOWS[0].parent / "audit.yml").read_text(encoding="utf-8")
    assert "schedule:" in text and "cron:" in text
    assert re.search(r"pip-audit==\d+\.\d+\.\d+", text), "the auditor itself must be version-pinned"
    assert "requirements.txt" in text
