#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Caller-owned application wrapper: run the C smoke against the live provider.

Reads the runner-provided P11LAB_MODULE/PIN/output locations from the
environment, so the same caller code works wherever `p11lab run` executes it.
Usage: consumer-app.py SMOKE_BIN [--label LABEL]
"""
import os
import subprocess
import sys
from pathlib import Path


def main(argv):
    if len(argv) < 2 or not argv[1]:
        print("consumer-app.py: smoke binary path is required", file=sys.stderr)
        return 2
    label = "P11Lab"
    rest = argv[2:]
    if rest[:1] == ["--label"] and len(rest) == 2:
        label = rest[1]
    elif rest:
        print("consumer-app.py: unexpected arguments", file=sys.stderr)
        return 2
    try:
        module = os.environ["P11LAB_MODULE"]
        out = Path(os.environ["P11LAB_OUTPUT_DIR"]) / "crypto"
    except KeyError as error:
        print(f"consumer-app.py: runner environment is missing {error}", file=sys.stderr)
        return 2
    smoke = Path(argv[1])
    if not smoke.is_file():
        print(f"consumer-app.py: smoke binary is missing: {smoke}", file=sys.stderr)
        return 2
    command = [str(smoke), "--module", module, "--token-label", label,
               "--output", str(out), "--key-mode", "generated"]
    pin_file = os.environ.get("P11LAB_PIN_FILE", "")
    if pin_file:
        command += ["--pin-file", pin_file]
    completed = subprocess.run(command)
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
