"""The 15-minute auto-delete must stay silent (user requirement) yet leave an auditable trace."""
import ast
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")


def _node(name: str):
    for node in ast.walk(ast.parse(SOURCE)):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


def _function(name: str) -> str:
    return ast.get_source_segment(SOURCE, _node(name)) or ""


def _identifiers(name: str) -> set[str]:
    """Every name/attribute the function really uses (docstrings and comments are not code)."""
    found: set[str] = set()
    for sub in ast.walk(_node(name)):
        if isinstance(sub, ast.Name):
            found.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            found.add(sub.attr)
    return found


def test_auto_delete_loop_never_notifies_the_user():
    used = _identifiers("quarantine_due_loop")
    forbidden = {"set_notice", "_play_security_alarm", "SnackBar", "AlertDialog", "show_dialog", "open", "notification_status_text",
                 "play"}
    assert not (used & forbidden), f"silent auto-delete must not use: {sorted(used & forbidden)}"


def test_auto_delete_loop_uses_the_vault_deadline_and_is_audited():
    body = _function("quarantine_due_loop")
    assert "scanner.vault.process_due" in body
    assert "_audit_threat" in body and "dihapus otomatis" in body
    assert "asyncio.sleep(15)" in body


def test_loop_is_started_with_the_dashboard():
    assert "page.run_task(quarantine_due_loop)" in SOURCE
