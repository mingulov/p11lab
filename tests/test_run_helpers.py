"""Pins for the shared direct/proxy run helpers (review A6).

The A6 refactor is behavior-identical by construction; these tests pin the
extracted semantics (exit precedence, redaction boundary, credential/state
staging) so the two runners cannot silently diverge again.
"""
import signal

import pytest

from p11lab.run import (
    compute_exit_code,
    prepare_state_mount,
    redact_text,
    stage_credential_inputs,
)


@pytest.mark.parametrize("kwargs,expected", [
    ({"app_returncode": 3, "app_completed": True}, 3),
    ({"app_returncode": 0, "app_completed": True}, 0),
    ({"app_returncode": 0, "app_completed": True, "lifecycle": ["x"]}, 1),
    ({"app_returncode": 3, "app_completed": True, "interrupted_signal": signal.SIGTERM}, 3),
    ({"app_returncode": None, "app_completed": False, "interrupted_signal": signal.SIGTERM}, 128 + signal.SIGTERM),
    ({"app_returncode": None, "app_completed": False, "timed_out": True}, 124),
    ({"app_returncode": 5, "app_completed": False}, 5),
    ({"app_returncode": None, "app_completed": False, "lifecycle": ["x"]}, 1),
    ({"app_returncode": None, "app_completed": False, "cleanup": ["y"]}, 1),
    ({"app_returncode": None, "app_completed": False}, 0),
])
def test_compute_exit_code_precedence(kwargs, expected):
    base = {"app_returncode": None, "app_completed": False, "interrupted_signal": None,
            "timed_out": False, "lifecycle": [], "cleanup": []}
    assert compute_exit_code(**(base | kwargs)) == expected


def test_redact_text_trims_truncation_boundary_first():
    # 'xx123' retained with truncation: the trailing '123' could be half of
    # the secret, so the boundary trim (len-1) drops it before redaction.
    assert redact_text("ok 1234 xx123", True, ["1234"]) == "ok [REDACTED] xx"
    assert redact_text("ok 1234 xx123", False, ["1234"]) == "ok [REDACTED] xx123"


def test_redact_text_replaces_longest_first():
    assert redact_text("abc bc", False, ["bc", "abc"]) == "[REDACTED] [REDACTED]"


class _Spec:
    def __init__(self, inputs):
        self.inputs = inputs


def _descriptor():
    return {"inputs": {"P11LAB_PIN_FILE": {"secret": True}, "P11LAB_PIN": {"secret": True},
                       "P11LAB_LABEL": {"secret": False}}}


def test_stage_credential_inputs_snapshot_and_envfile(tmp_path):
    pin = tmp_path / "pin"
    pin.write_bytes(b"1234\n")
    spec = _Spec({"P11LAB_PIN_FILE": str(pin), "P11LAB_PIN": "9",
                  "P11LAB_LABEL": "L", "P11LAB_STATE_DIR": str(tmp_path)})
    staging = tmp_path / "staging"
    staging.mkdir()
    inputs, mounts, envfile = stage_credential_inputs(
        spec, _descriptor(), {"P11LAB_PIN_FILE": b"1234"}, staging)
    assert inputs == {"P11LAB_PIN_FILE": "/run/p11lab-input/P11LAB_PIN_FILE",
                      "P11LAB_PIN": "9", "P11LAB_LABEL": "L"}
    snapshot = tmp_path / "staging" / "P11LAB_PIN_FILE"
    assert snapshot.read_bytes() == b"1234"
    assert snapshot.stat().st_mode & 0o777 == 0o444
    assert mounts == ["--mount", f"type=bind,src={snapshot},dst=/run/p11lab-input/P11LAB_PIN_FILE,readonly"]
    assert envfile.read_text() == ("P11LAB_PIN_FILE=/run/p11lab-input/P11LAB_PIN_FILE\n"
                                   "P11LAB_PIN=9\nP11LAB_LABEL=L\n")
    assert envfile.stat().st_mode & 0o777 == 0o600


def test_stage_credential_inputs_refuses_comma_source(tmp_path):
    weird = tmp_path / "a,b"
    weird.mkdir()
    pin = weird / "pin"
    pin.write_bytes(b"1")
    spec = _Spec({"P11LAB_PIN_FILE": str(pin)})
    (tmp_path / "staging").mkdir()
    with pytest.raises(ValueError, match="commas"):
        stage_credential_inputs(spec, _descriptor(), {"P11LAB_PIN_FILE": b"1"}, tmp_path / "staging")


class _Engine:
    def __init__(self, volume=None, error=None):
        self.volume_result = volume
        self.error = error

    def volume(self, name, labels, staging):
        if self.error is not None:
            raise self.error
        return self.volume_result


def test_prepare_state_mount_binds_caller_directory(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    owned, box = [], {}
    prepare_state_mount(_Spec({"P11LAB_STATE_DIR": str(state)}), _Engine(), "run", {}, owned, box)
    assert box["state_mount"] == f"type=bind,src={state.resolve()},dst=/var/lib/p11lab"
    assert box["state_directory"] is None
    assert box["state_ownership"]["mode"] == oct(state.stat().st_mode & 0o777)
    assert owned == []


def test_prepare_state_mount_provisions_owned_volume(tmp_path):
    owned, box = [], {}
    prepare_state_mount(_Spec({}), _Engine(volume="vol-1"), "run", {"k": "v"}, owned, box)
    assert box["state_mount"] == "type=volume,src=vol-1,dst=/var/lib/p11lab,volume-nocopy"
    assert box["state_directory"].is_dir()
    assert owned == [("volume", "vol-1")]


def test_prepare_state_mount_keeps_partial_state_on_engine_failure():
    from p11lab.docker import DockerError

    owned, box = [], {}
    with pytest.raises(DockerError):
        prepare_state_mount(_Spec({}), _Engine(error=DockerError("boom")), "run", {}, owned, box)
    # The provisioned directory and its ownership stay visible for cleanup
    # and receipt accounting, exactly as the inline code left them.
    assert box["state_directory"].is_dir()
    assert box["state_ownership"]["uid"] >= 0
    assert "state_mount" not in box and owned == []
