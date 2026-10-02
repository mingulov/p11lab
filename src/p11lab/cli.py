"""Read-only installed catalogue command interface."""

import argparse
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
    args = parser.parse_args(argv)
    try:
        if args.command == "describe":
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
