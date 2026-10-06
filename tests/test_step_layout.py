"""Step-file layout: flat copies must import without checkout-depth assumptions.

The direct lane copies the dual-mode step file flat to /workspace, where a
``parents[2]`` assumption raises IndexError at import. The file resolves its
work directory for both layouts (repo root for checkouts, own dir for flat
copies) and its resources from the installed package; these tests pin that
contract behaviorally (a flat copy dispatches), statically (no depth-indexed
``parents`` attribute access remains to regress), and by unit (the resolver
maps both layouts).
"""

import ast
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

STEP_FILE = Path(__file__).resolve().parents[1] / "tests" / "integration" / "test_bouncyhsm.py"


def test_flat_copied_step_file_dispatches(tmp_path):
    """A flat copy (no repo parents) must reach step dispatch, not IndexError."""
    flat = tmp_path / "flat"
    flat.mkdir()
    dst = flat / "test_bouncyhsm.py"
    shutil.copy(STEP_FILE, dst)
    completed = subprocess.run(
        [sys.executable, str(dst), "no-such-step"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 2, completed.stderr
    assert "usage: test_bouncyhsm.py" in completed.stderr


def test_step_file_has_no_depth_indexed_parents():
    """No parents[N] subscript may regress into the dual-mode step file."""
    tree = ast.parse(STEP_FILE.read_text())
    hits = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "parents"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, int)
    ]
    assert hits == [], f"depth-indexed parents access at lines {hits}"


def _load_step_module():
    spec = importlib.util.spec_from_file_location("stepfile_layout", STEP_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_work_dir_repo_layout():
    module = _load_step_module()
    assert module._work_dir("/repo/tests/integration/test_bouncyhsm.py") == Path("/repo")


def test_work_dir_flat_copy():
    module = _load_step_module()
    assert module._work_dir("/workspace/test_bouncyhsm.py") == Path("/workspace")
