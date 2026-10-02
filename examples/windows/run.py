"""Minimal native BouncyHSM run on Windows (example, not a test harness).

Installs nothing: takes an installed prefix, provisions one token under
out/state (or reuses it), runs the independent C consumer, and prints the
receipt summary. Usage:
    python run.py --prefix PREFIX --channel release|rolling --tools DIR
                  [--state DIR] [--http-port N] [--tcp-port N]
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--prefix", required=True)
    args.add_argument("--channel", required=True, choices=("release", "rolling"))
    args.add_argument("--tools", required=True)
    args.add_argument("--state", default=None)
    args.add_argument("--http-port", default=None)
    args.add_argument("--tcp-port", default=None)
    opts = args.parse_args()

    from p11lab.models import RunSpec
    from p11lab.native import load_bouncyhsm_installation, run_native_bouncyhsm

    prefix = Path(opts.prefix)
    installed = load_bouncyhsm_installation(
        prefix,
        environment="bouncyhsm",
        channel=opts.channel,
        platform="windows/amd64",
    )
    tools = Path(opts.tools)
    out = Path("out")
    secrets = Path("secrets")
    secrets.mkdir(exist_ok=True)
    (secrets / "pin").write_bytes(b"1234")
    (secrets / "so-pin").write_bytes(b"12345678")
    inputs = {}
    state = Path(opts.state) if opts.state else out / "state"
    # Fresh state provisions (credentials required); completed state reuses
    # the token without provisioning credentials. The consumer still gets
    # its own PIN file either way.
    state.mkdir(parents=True, exist_ok=True)
    inputs["P11LAB_STATE_DIR"] = str(state)
    if not (state / "bouncyhsm" / "complete").exists():
        inputs["P11LAB_PIN_FILE"] = str(secrets / "pin")
        inputs["P11LAB_SO_PIN_FILE"] = str(secrets / "so-pin")
    if opts.http_port:
        inputs["P11LAB_HTTP_PORT"] = opts.http_port
    if opts.tcp_port:
        inputs["P11LAB_TCP_PORT"] = opts.tcp_port
    module = prefix / "payload" / installed.manifest["module"]
    spec = RunSpec(
        "bouncyhsm",
        opts.channel,
        "native",
        installed.artifact,
        "host",
        None,
        None,
        (
            str(tools / "p11lab-smoke.exe"),
            "--module",
            str(module),
            "--token-label",
            "P11Lab",
            "--pin-file",
            str(secrets / "pin"),
            "--output",
            str(out / "smoke"),
            "--key-mode",
            "generated",
        ),
        inputs,
        out,
        Path("."),
        300,
        prefix,
    )
    result = run_native_bouncyhsm(spec, installed)
    receipt = json.loads(Path(result.receipt_path).read_text())
    print(
        json.dumps(
            {
                "exit_code": result.exit_code,
                "slot": receipt["state"]["slot"],
                "stages": [s["phase"] for s in receipt["stages"]],
                "http_port": receipt["execution"]["http_port"],
                "tcp_port": receipt["execution"]["tcp_port"],
                "lifecycle_errors": list(result.lifecycle_errors),
                "cleanup_errors": list(result.cleanup_errors),
            },
            indent=2,
        )
    )
    return 0 if result.exit_code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
