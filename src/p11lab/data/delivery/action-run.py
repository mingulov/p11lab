#!/usr/bin/env python3
"""Reusable-action core: fetch a handoff by digest and run the caller app.

Invoked by action.yml after p11lab and ORAS are installed. All acquisition
uses immutable digest references; tags are never trusted. The child `p11lab
run` receives a scrubbed environment plus only the declared provider inputs:
the host environment and publisher credentials are never forwarded into
providers. The application exit code propagates unchanged.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


# OS essentials allowed into the child process; everything else (including
# CI/publisher credentials) stays outside the provider boundary.
ALLOWED_ENV = {"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR",
               "USERPROFILE", "COMSPEC", "LANG", "LC_ALL", "TZ"}


def _is_loopback(registry: str) -> bool:
    host = urlsplit("//" + registry).hostname or ""
    return host in {"localhost", "127.0.0.1", "::1"}


def _display(argv):
    """Render argv for logs with `--input` values redacted to names only.

    Provider inputs travel as `--input NAME=VALUE`; values may be secrets
    when callers pass them inline instead of by file path, so logs carry
    `NAME=***` while the executed argv keeps the real values.
    """
    shown = []
    mask = False
    for word in argv:
        if mask:
            shown.append(word.split("=", 1)[0] + "=***")
            mask = False
        elif word == "--input":
            shown.append(word)
            mask = True
        elif word.startswith("--input="):
            shown.append("--input=" + word[len("--input="):].split("=", 1)[0] + "=***")
        else:
            shown.append(word)
    return shown


def _run(argv, *, env, cwd):
    print("+ " + " ".join(_display(argv)), flush=True)
    result = subprocess.run(argv, env=env, cwd=cwd)
    return result.returncode


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run a caller app from a P11Lab handoff.")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--channel", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--handoff-digest", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--inputs", default="")
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--timeout", required=True)
    parser.add_argument("--working-directory", required=True)
    parser.add_argument("--oras", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--local-proof", action="store_true",
                        help="Proceed past a blocked verdict for local mechanics proof only; never used by action.yml.")
    args = parser.parse_args(argv)

    from p11lab.publish import require_digest_reference, show_handoff, validate_action_inputs

    try:
        values = validate_action_inputs({
            "environment": args.environment, "channel": args.channel, "mode": args.mode,
            "registry": args.registry, "handoff-digest": args.handoff_digest, "command": args.command,
            "inputs": args.inputs, "state-dir": args.state_dir, "timeout": args.timeout,
            "working-directory": args.working_directory})
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 2
    if os.name == "nt" and values["mode"] == "direct":
        print("action-run: direct mode requires Linux runners with Docker", file=sys.stderr)
        return 2
    run_dir = Path(args.run_dir)
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(f"action-run: run directory must be fresh: {run_dir}", file=sys.stderr)
        return 2
    work = Path(values["working-directory"])
    if not work.is_dir():
        print(f"action-run: working directory is missing: {work}", file=sys.stderr)
        return 2
    oras = args.oras
    handoff_ref = values["registry"] + "@" + values["handoff-digest"]
    try:
        require_digest_reference(handoff_ref)
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 2
    plain_http = ["--plain-http"] if _is_loopback(values["registry"]) else []
    auth = run_dir / "oras-auth.json"
    auth.write_text('{"auths":{}}\n')
    handoff_dir = run_dir / "handoff"
    handoff_dir.mkdir()
    pull = [oras, "pull", "--registry-config", str(auth), "--no-tty", "-o", str(handoff_dir),
            *plain_http, handoff_ref]
    if _run(pull, env=dict(os.environ), cwd=str(work)):
        print("action-run: anonymous handoff fetch failed", file=sys.stderr)
        return 1
    handoff_file = handoff_dir / "handoff.json"
    if not handoff_file.is_file():
        print("action-run: pulled handoff has no handoff.json", file=sys.stderr)
        return 1
    try:
        handoff = show_handoff(handoff_file)
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 1
    catalogue = handoff["catalogue"]
    if handoff["registry"] != values["registry"] or catalogue["environment"] != values["environment"] \
            or catalogue["channel"] != values["channel"]:
        print("action-run: handoff binds a different registry/environment/channel", file=sys.stderr)
        return 1
    expected_role = "runtime" if values["mode"] == "direct" else "native"
    if catalogue.get("runtime_role") != expected_role:
        print(f"action-run: handoff runtime role {catalogue.get('runtime_role')} does not serve mode {values['mode']}",
              file=sys.stderr)
        return 1
    if handoff["admission"]["status"] != "eligible" and not args.local_proof:
        print("action-run: handoff admission is not eligible; refusing to run", file=sys.stderr)
        return 1
    if handoff["admission"]["status"] != "eligible":
        print("action-run: LOCAL-PROOF OVERRIDE: proceeding despite blocked admission: "
              + "; ".join(handoff["admission"]["blockers"]))
    try:
        binary = require_digest_reference(handoff["binary"]["reference"])
    except ValueError as error:
        print(f"action-run: {error}", file=sys.stderr)
        return 1
    if binary["repository"] != values["registry"]:
        print("action-run: handoff binary points outside the selected registry", file=sys.stderr)
        return 1
    child_env = {key: value for key, value in os.environ.items() if key in ALLOWED_ENV}
    output_dir = run_dir / "run-output"
    command = [sys.executable, "-m", "p11lab", "run", values["environment"], "--channel", values["channel"],
               "--mode", values["mode"], "--output-dir", str(output_dir), "--cwd", str(work),
               "--timeout", str(values["timeout_seconds"])]
    if values["mode"] == "direct":
        docker_config = run_dir / "docker-config"
        docker_config.mkdir()
        fetch_env = dict(child_env, DOCKER_CONFIG=str(docker_config))
        if _run(["docker", "pull", handoff["binary"]["reference"]], env=fetch_env, cwd=str(work)):
            print("action-run: anonymous binary pull failed", file=sys.stderr)
            return 1
        inspected = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}",
                                    handoff["binary"]["reference"]],
                                   env=fetch_env, cwd=str(work), capture_output=True, text=True)
        engine_id = inspected.stdout.strip()
        if inspected.returncode or not engine_id.startswith("sha256:"):
            print("action-run: pulled binary has no local engine ID", file=sys.stderr)
            return 1
        print(f"action-run: binary {handoff['binary']['reference']} resolves to engine {engine_id}")
        command += ["--artifact", engine_id]
        child_env = fetch_env
    else:
        bundle_dir = run_dir / "bundle"
        bundle_dir.mkdir()
        if _run([oras, "pull", "--registry-config", str(auth), "--no-tty", "-o", str(bundle_dir),
                 *plain_http, handoff["binary"]["reference"]], env=dict(os.environ), cwd=str(work)):
            print("action-run: anonymous bundle pull failed", file=sys.stderr)
            return 1
        archives = sorted(bundle_dir.glob("*.tar.gz"))
        if len(archives) != 1 or hashlib.sha256(archives[0].read_bytes()).hexdigest() != handoff["binary"]["file_sha256"]:
            print("action-run: pulled bundle does not match the handoff file digest", file=sys.stderr)
            return 1
        prefix = run_dir / "prefix"
        install = [sys.executable, "-m", "p11lab", "install", values["environment"],
                   "--channel", values["channel"], "--artifact", str(archives[0]),
                   "--sha256", handoff["binary"]["file_sha256"], "--platform", handoff["binary"]["platform"],
                   "--prefix", str(prefix)]
        print("+ " + " ".join(install), flush=True)
        installed = subprocess.run(install, env=child_env, cwd=str(work), capture_output=True, text=True)
        print(installed.stdout, end="")
        if installed.returncode:
            print(installed.stderr, end="", file=sys.stderr)
            print("action-run: native bundle installation failed", file=sys.stderr)
            return installed.returncode
        command += ["--installed-prefix", str(prefix)]
    for entry in values["input_entries"]:
        command += ["--input", entry]
    if values["state-dir"]:
        command += ["--state-dir", values["state-dir"]]
    command += ["--", *values["command_argv"]]
    print(f"action-run: inputs: {', '.join(e.split('=', 1)[0] for e in values['input_entries']) or '(none)'}")
    print(f"action-run: argv: {values['command_argv']!r}")
    code = _run(command, env=child_env, cwd=str(work))
    app_returncode = ""
    receipt = output_dir / "receipt.json"
    if receipt.is_file():
        try:
            record = json.loads(receipt.read_text())
            app_returncode = "" if record.get("app_returncode") is None else str(record["app_returncode"])
        except ValueError:
            pass
    outputs = {"exit-code": str(code), "app-returncode": app_returncode, "receipt-path": str(receipt),
               "handoff-sha256": hashlib.sha256(handoff_file.read_bytes()).hexdigest()}
    (run_dir / "action-outputs.env").write_text("".join(f"{k}={v}\n" for k, v in outputs.items()))
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as stream:
            stream.write("".join(f"{k}={v}\n" for k, v in outputs.items()))
    print(json.dumps(outputs, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
