"""Step-file layout: repo root for checkouts, own dir for flat copies.

The direct lane copies the dual-mode step file flat to /workspace, where
``parents[2]`` does not exist (IndexError at import). The resolver must
tolerate both layouts; the image ships installed p11lab for flat copies.
"""

import importlib.util
from pathlib import Path

STEP_FILE = Path(__file__).resolve().parents[1] / "tests" / "integration" / "test_bouncyhsm.py"


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
