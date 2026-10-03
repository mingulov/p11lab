"""Step-file layout: flat copies must import without checkout-depth assumptions.

The direct lane copies the dual-mode step file flat to /workspace, where a
``parents[2]`` assumption raises IndexError at import. The file resolves its
resources from the installed package instead; these tests pin that contract
both behaviorally (a flat copy dispatches) and statically (no depth-indexed
``parents`` access remains to regress).
"""

import ast
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
