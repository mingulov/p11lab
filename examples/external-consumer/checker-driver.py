#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Optional checker lane: public pkcs11-check CLI at the pinned revision.

Runs as an ordinary application inside `p11lab run` against the live token.
Discovers the single P11Lab token-present slot, then invokes the checker's
public CLI with the frozen smoke profile and the controlled checker
environment. Exits with the checker return code.
"""
import os
import subprocess
import sys
from pathlib import Path

import pkcs11_check.testcases as tests
from pkcs11_check.core.loader import load_module
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import CKR_OK

from p11lab.checker import checker_environment, load_profile
from p11lab.secrets import credential_text


def main():
    module = Path(os.environ["P11LAB_MODULE"])
    output = Path(os.environ["P11LAB_OUTPUT_DIR"]) / "checker"
    output.mkdir(parents=True, exist_ok=True)
    p11 = load_module(module, interface="auto")
    slots = p11.get_slots(token_present=True)
    selected = [(i, s.slot_id) for i, s in enumerate(slots) if s.get_token().label == "P11Lab"]
    if len(selected) != 1:
        print("checker-driver: token identity must select exactly one token-present slot",
              file=sys.stderr)
        return 2
    slot, native_id = selected[0]
    expect_rv(p11.raw.C_Finalize(None), CKR_OK)
    print(f"checker slot: index={slot} native={native_id}", flush=True)
    # One trailing LF frames the credential file and is not part of the PIN,
    # exactly as in provisioning (runtime-contract); anything else fails here
    # instead of reaching the token with a divergent value.
    pin = credential_text(Path(os.environ["P11LAB_PIN_FILE"]).read_bytes(), file=True)
    so_pin = credential_text(Path(os.environ["P11LAB_SO_PIN_FILE"]).read_bytes(), file=True)
    installed_root = Path(tests.__file__).resolve().parent
    targets = [str(installed_root / node) for node in load_profile()["nodes"]]
    argv = [sys.executable, "-m", "pkcs11_check", "test", "--module", str(module),
            "--slot", str(slot), "--interface", "auto", "--isolation", "file",
            "--timeout", "180", "--ignore-disabled-tests", "--no-collection-cache",
            "--key-inject", "off", "--recover-mode", "off", "--output", "json",
            "--output-file", str(output / "results.json"),
            "--state-file", str(output / "state.json"),
            "--policy-file", str(output / "policy.json"), *targets]
    env = checker_environment(output, pin, so_pin)
    proc = subprocess.run(argv, cwd=output, env=env)
    print(f"checker returncode: {proc.returncode}", flush=True)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
