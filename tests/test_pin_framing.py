"""PIN file framing semantic shared by provisioning and login (review D3).

Provisioning (secrets/common.sh) and every login path (smoke.c, the
checker driver via credential_text) agree: one optional trailing LF
frames the file and is not part of the PIN. The C side is covered by
the consumer fixture test; this pins the Python intake rule the
checker driver reuses. (secrets.py itself is outside this fixup's
owned files, so this file only pins its observed contract.)
"""
import pytest

from p11lab.secrets import credential_text


@pytest.mark.parametrize("data,expected", [
    (b"1234", "1234"),
    (b"1234\n", "1234"),
])
def test_file_pin_strips_at_most_one_trailing_lf(data, expected):
    assert credential_text(data, file=True) == expected


@pytest.mark.parametrize("data", [b"", b"\n", b"1234\n\n", b"12\n34", b"12\r34", b"12\x0034"])
def test_file_pin_rejects_empty_and_multiline(data):
    with pytest.raises(ValueError):
        credential_text(data, file=True)


def test_scalar_pin_has_no_framing():
    assert credential_text(b"1234", file=False) == "1234"
    with pytest.raises(ValueError):
        credential_text(b"1234\n", file=False)


def test_embedded_windows_checker_driver_reuses_credential_text():
    """Sol-5: the embedded driver must share the file framing rule.

    A raw read_text() would forward a framing LF into P11TEST_PIN and
    diverge from provisioning; both populated PIN files must go through
    credential_text in file mode.
    """
    from pathlib import Path

    workflow = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "clean-consumer-windows.yml"
    text = workflow.read_text()
    assert "from p11lab.secrets import credential_text" in text
    for var in ("P11LAB_PIN_FILE", "P11LAB_SO_PIN_FILE"):
        line = next(line for line in text.splitlines() if var in line and "=" in line and "${{" not in line
                    and "os.environ.get" not in line)
        assert "credential_text(" in line and "read_bytes()" in line and "file=True" in line, line
    assert 'P11LAB_PIN_FILE"]).read_text()' not in text
    assert 'P11LAB_SO_PIN_FILE"]).read_text()' not in text
