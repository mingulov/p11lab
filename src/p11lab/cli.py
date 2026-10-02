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
            command.add_argument("--debug-output-dir", type=Path, help="export a separate matched binary debug companion")
    install = commands.add_parser("install", help="install a verified local native candidate")
    install.add_argument("id")
    install.add_argument("--channel", required=True)
    install.add_argument("--artifact", required=True, type=Path)
    install.add_argument("--sha256", required=True)
    install.add_argument("--platform", required=True)
    install.add_argument("--prefix", required=True, type=Path)
    command = commands.add_parser("run", help="run an application in an owned provider instance")
    command.add_argument("id")
    command.add_argument("--channel", required=True)
    command.add_argument("--mode", choices=("direct", "proxy", "native"), default="direct")
    command.add_argument("--where", choices=("provider", "container", "host"))
    artifact_choice = command.add_mutually_exclusive_group(required=True)
    artifact_choice.add_argument("--artifact", help="exact local engine image ID or native archive")
    artifact_choice.add_argument("--installed-prefix", type=Path)
    command.add_argument("--sha256", help="required SHA256 for native archive input")
    command.add_argument("--control-dir", type=Path, help="native private control directory")
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
        if args.command == "install":
            from .native import install_native_bundle, MODULE
            from .models import ArtifactRef
            artifact = ArtifactRef('bundle', str(args.artifact.resolve()), args.sha256, args.platform)
            installed = install_native_bundle(artifact, args.prefix, environment=args.id, channel=args.channel)
            print(json.dumps({'artifact': asdict(installed.artifact), 'prefix': str(installed.prefix),
                              'module': str(installed.prefix / 'payload' / MODULE),
                              'configuration': 'chosen control directory/softhsm2.conf at runtime',
                              'receipt_path': str(installed.receipt_path)}, indent=2))
        elif args.command == "run":
            from .models import ArtifactRef, RunSpec
            from .run import run_application
            def artifact(reference):
                return ArtifactRef("docker-local", reference, reference.removeprefix("sha256:"), args.platform) if reference else None
            if args.installed_prefix is not None:
                if args.mode != 'native' or args.sha256:
                    raise ValueError('installed-prefix requires native mode without archive SHA256')
                from .bundle import read_installation
                selected_artifact = read_installation(args.installed_prefix, environment=args.id,
                    channel=args.channel, platform=args.platform).artifact
            elif args.mode == 'native':
                if not args.sha256:
                    raise ValueError('native archive input requires --sha256')
                selected_artifact = ArtifactRef('bundle', str(Path(args.artifact).resolve()), args.sha256, args.platform)
            else:
                if args.sha256 or args.control_dir:
                    raise ValueError('native archive/control options require native mode')
                selected_artifact = artifact(args.artifact)
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
            if args.control_dir is not None:
                if 'P11LAB_CONTROL_DIR' in inputs:
                    raise ValueError('duplicate control directory input')
                inputs['P11LAB_CONTROL_DIR'] = str(args.control_dir)
            result = run_application(RunSpec(args.id, args.channel, args.mode, selected_artifact,
                args.where or {"direct": "provider", "proxy": "host", "native": "host"}[args.mode],
                artifact(args.consumer_image), artifact(args.client_artifact), tuple(application_argv), inputs,
                args.output_dir, args.cwd, args.timeout, args.installed_prefix))
            record = asdict(result)
            if args.mode == 'native':
                execution = json.loads(result.receipt_path.read_text())['execution']
                record.update(module=execution['module'], configuration=execution['configuration'])
            print(json.dumps(record, default=str, indent=2, sort_keys=True))
            return result.exit_code
        elif args.command in {"resolve", "build"}:
            spec = load_environment(args.id, args.channel)
            if args.command == "resolve":
                from .sources import resolve_sources
                result = resolve_sources(spec, output_dir=args.output_dir)
            else:
                from .build import build_artifact
                if args.role == 'native' and args.debug_output_dir is not None:
                    raise ValueError('native build does not export container debug companions')
                artifact = build_artifact(spec, args.role, args.output_dir)
                result = asdict(artifact)
                if args.debug_output_dir is not None:
                    from .debug import export_debug_companion
                    export_debug_companion(spec, artifact, args.output_dir, args.debug_output_dir)
            print(json.dumps(result, indent=2, sort_keys=True))
        elif args.command == "describe":
            spec = load_environment(args.id, args.channel)
            spec['delivery_formats'] = {
                'container': spec['channel_spec']['status'],
                'native': spec.get('native_targets', {'status': 'not-packaged', 'reason': 'No native packaging target is declared.'}),
            }
            print(json.dumps(spec, indent=2, sort_keys=True))
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
