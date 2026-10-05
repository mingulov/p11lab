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
    # Delivery gates decide only; they never push, publish, or reach the network.
    publish = commands.add_parser("publish", help="source-first delivery gates (decide only; never publish)")
    publish.add_argument("operation", choices=("seal-sources", "seal-native", "verify-readback", "check-inputs", "admit", "expose", "show-handoff"))
    publish.add_argument("id", nargs="?")
    publish.add_argument("--channel")
    publish.add_argument("--target", default="debian13-amd64")
    publish.add_argument("--resolved-dir", type=Path)
    publish.add_argument("--sealed-receipt", type=Path)
    publish.add_argument("--sealed-manifest", type=Path)
    publish.add_argument("--pulled-dir", type=Path)
    publish.add_argument("--transcript", type=Path)
    publish.add_argument("--extract-dir", type=Path)
    publish.add_argument("--build-receipt", type=Path)
    publish.add_argument("--manifest", type=Path)
    publish.add_argument("--readback-proof", type=Path)
    publish.add_argument("--artifact-kind", choices=("docker-local", "bundle"))
    publish.add_argument("--artifact-reference")
    publish.add_argument("--artifact-digest")
    publish.add_argument("--platform", default="linux/amd64")
    publish.add_argument("--registry")
    publish.add_argument("--evidence-dir", type=Path)
    publish.add_argument("--handoff", type=Path)
    publish.add_argument("--output-dir", type=Path)
    publish.add_argument("--producer-wheel-sha256")
    publish.add_argument("--admission", type=Path)
    publish.add_argument("--pushed-digest")
    publish.add_argument("--pushed-tag")
    publish.add_argument("--pushed-size", type=int)
    publish.add_argument("--local-inspect", type=Path)
    publish.add_argument("--pulled-inspect", type=Path)
    publish.add_argument("--pulled-bundle", type=Path)
    publish.add_argument("--source-manifest-digest")
    publish.add_argument("--source-manifest", type=Path)
    arguments = list(sys.argv[1:] if argv is None else argv)
    application_argv = []
    if arguments and arguments[0] == "run" and "--" in arguments:
        boundary = arguments.index("--")
        application_argv = arguments[boundary + 1:]
        arguments = arguments[:boundary]
    args = parser.parse_args(arguments)
    try:
        if args.command == "publish":
            from . import publish as delivery
            operation = args.operation
            if operation == "seal-sources":
                if not args.id or not args.channel or not args.resolved_dir or not args.output_dir:
                    raise ValueError("seal-sources requires an ID, --channel, --resolved-dir and --output-dir")
                spec = load_environment(args.id, args.channel)
                resolved = json.loads((args.resolved_dir / "resolved-sources.json").read_text())
                print(json.dumps(delivery.seal_sources(spec, resolved, args.output_dir), indent=2, sort_keys=True))
            elif operation == "seal-native":
                if not args.id or not args.channel or not args.output_dir:
                    raise ValueError("seal-native requires an ID, --channel and --output-dir")
                from .catalog import load_native_target
                spec = load_native_target(args.id, args.channel, args.target)
                print(json.dumps(delivery.seal_native_source(spec, args.output_dir), indent=2, sort_keys=True))
            elif operation == "verify-readback":
                if not args.sealed_receipt or not args.pulled_dir or not args.transcript or not args.extract_dir:
                    raise ValueError("verify-readback requires --sealed-receipt, --pulled-dir, --transcript and --extract-dir")
                print(json.dumps(delivery.verify_readback(args.sealed_receipt, args.pulled_dir,
                    transcript_path=args.transcript, extract_dir=args.extract_dir), indent=2, sort_keys=True))
            elif operation == "check-inputs":
                if not args.id or not args.channel or not args.sealed_manifest or not args.build_receipt:
                    raise ValueError("check-inputs requires an ID, --channel, --sealed-manifest and --build-receipt")
                sealed = json.loads(args.sealed_manifest.read_text())
                spec = load_environment(args.id, args.channel)
                manifest = json.loads(args.manifest.read_text()) if args.manifest else None
                print(json.dumps(delivery.check_input_match(sealed, args.build_receipt, spec, manifest=manifest),
                                 indent=2, sort_keys=True))
            elif operation == "admit":
                required = (args.id, args.channel, args.sealed_receipt, args.sealed_manifest, args.readback_proof,
                            args.build_receipt, args.artifact_kind, args.artifact_reference, args.artifact_digest,
                            args.registry, args.output_dir, args.producer_wheel_sha256,
                            args.source_manifest_digest, args.source_manifest)
                if not all(required):
                    raise ValueError("admit requires ID/channel, sealed receipt+manifest, readback proof, build receipt,"
                                     " artifact kind/reference/digest, registry, output dir, producer wheel identity"
                                     " and pushed source manifest digest+bytes")
                sealed = json.loads(args.sealed_manifest.read_text())
                if sealed.get("runtime_role") == "native":
                    from .catalog import load_native_target
                    spec = load_native_target(args.id, args.channel, sealed.get("target", args.target))
                else:
                    spec = load_environment(args.id, args.channel)
                manifest = json.loads(args.manifest.read_text()) if args.manifest else None
                result = delivery.admit(artifact_kind=args.artifact_kind, artifact_reference=args.artifact_reference,
                    artifact_digest=args.artifact_digest, platform=args.platform, sealed_receipt_path=args.sealed_receipt,
                    sealed_manifest=sealed, readback_proof=json.loads(args.readback_proof.read_text()),
                    build_receipt_path=args.build_receipt, spec=spec, registry=args.registry,
                    evidence_dir=args.evidence_dir, out_dir=args.output_dir,
                    producer={"p11lab_wheel_sha256": args.producer_wheel_sha256}, manifest=manifest,
                    source_manifest_digest=args.source_manifest_digest, source_manifest_path=args.source_manifest)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0 if result["status"] == "eligible" else 3
            elif operation == "expose":
                required = (args.admission, args.pushed_digest, args.pushed_tag, args.pushed_size,
                            args.registry, args.output_dir)
                if not all(required):
                    raise ValueError("expose requires --admission, --pushed-digest, --pushed-tag, --pushed-size,"
                                     " --registry and --output-dir, plus readback identity")
                print(json.dumps(delivery.expose(admission_path=args.admission, pushed_digest=args.pushed_digest,
                    pushed_tag=args.pushed_tag, pushed_size=args.pushed_size, local_inspect_path=args.local_inspect,
                    pulled_inspect_path=args.pulled_inspect, pulled_bundle_path=args.pulled_bundle,
                    registry=args.registry, out_dir=args.output_dir), indent=2, sort_keys=True))
            elif operation == "show-handoff":
                if not args.handoff:
                    raise ValueError("show-handoff requires --handoff")
                print(json.dumps(delivery.show_handoff(args.handoff), indent=2, sort_keys=True))
        elif args.command == "install":
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
