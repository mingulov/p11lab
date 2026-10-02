"""Installed catalogue, verified source acquisition and runtime builds."""

import argparse
from dataclasses import asdict
from pathlib import Path
import json
import sys

from .catalog import CatalogError, list_environments, load_environment, package_data, validate_tools


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="p11lab", description="PKCS#11 provider environment catalogue")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list candidate environments and channel dispositions")
    listing.add_argument("--json", action="store_true")
    describe = commands.add_parser("describe", help="describe a selected environment/channel")
    describe.add_argument("id")
    describe.add_argument("--channel", required=True)
    commands.add_parser("validate", help="validate installed catalogue and declared assets")
    for name in ("resolve", "build"):
        command = commands.add_parser(name, help="acquire locked sources" if name == "resolve" else "build a locked runtime")
        command.add_argument("id")
        command.add_argument("--channel", required=True)
        command.add_argument("--output-dir", required=True, type=Path)
        if name == "build":
            command.add_argument("--role", default="runtime")
    command = commands.add_parser("run", help="run an application in an owned provider instance")
    command.add_argument("id")
    command.add_argument("--channel", required=True)
    command.add_argument("--mode", choices=("direct", "proxy", "native"), default="direct")
    command.add_argument("--where", choices=("provider", "container", "host"))
    command.add_argument("--artifact", required=True, help="exact local engine sha256 image ID")
    command.add_argument("--consumer-image")
    command.add_argument("--client-artifact")
    command.add_argument("--platform", default="linux/amd64")
    command.add_argument("--input", action="append", default=[], metavar="NAME=VALUE")
    command.add_argument("--state-dir", type=Path, help="existing caller-owned persistent state directory")
    command.add_argument("--output-dir", required=True, type=Path)
    command.add_argument("--cwd", type=Path, default=Path.cwd())
    command.add_argument("--timeout", type=int, default=300)
    arguments = list(sys.argv[1:] if argv is None else argv)
    application_argv = []
    if arguments and arguments[0] == "run" and "--" in arguments:
        boundary = arguments.index("--")
        application_argv = arguments[boundary + 1:]
        arguments = arguments[:boundary]
    args = parser.parse_args(arguments)
    try:
        if args.command == "run":
            from .models import ArtifactRef, RunSpec
            from .run import run_application
            def artifact(reference):
                return ArtifactRef("docker-local", reference, reference.removeprefix("sha256:"), args.platform) if reference else None
            inputs = {}
            for item in args.input:
                if "=" not in item:
                    raise ValueError("input requires NAME=VALUE")
                key, value = item.split("=", 1)
                if key in inputs:
                    raise ValueError("duplicate input name")
                inputs[key] = value
            if args.state_dir is not None:
                if "P11LAB_STATE_DIR" in inputs:
                    raise ValueError("duplicate state directory input")
                inputs["P11LAB_STATE_DIR"] = str(args.state_dir)
            result = run_application(RunSpec(args.id, args.channel, args.mode, artifact(args.artifact),
                args.where or {"direct": "provider", "proxy": "host", "native": "host"}[args.mode],
                artifact(args.consumer_image), artifact(args.client_artifact), tuple(application_argv), inputs,
                args.output_dir, args.cwd, args.timeout))
            print(json.dumps(asdict(result), default=str, indent=2, sort_keys=True))
            return result.exit_code
        elif args.command in {"resolve", "build"}:
            spec = load_environment(args.id, args.channel)
            if args.command == "resolve":
                from .sources import resolve_sources
                result = resolve_sources(spec, output_dir=args.output_dir)
            else:
                from .build import build_artifact
                result = asdict(build_artifact(spec, args.role, args.output_dir))
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "describe":
            print(json.dumps(load_environment(args.id, args.channel), indent=2, sort_keys=True))
        else:
            environments = list_environments()
            if args.command == "validate":
                validate_tools(json.loads(package_data("tools.json").read_text(encoding="utf-8")))
                print(f"Validated {len(environments)} candidate environments; distribution remains evidence-gated.")
            elif args.json:
                print(json.dumps(environments, indent=2, sort_keys=True))
            else:
                for spec in environments:
                    channels = ", ".join(f"{name}={value['status']}" for name, value in spec["channels"].items())
                    print(f"{spec['id']}: {channels}; distribution={spec['distribution']['status']}")
    except (CatalogError, OSError, ValueError) as error:
        print(f"p11lab: {error}", file=sys.stderr)
        return 2
    return 0
