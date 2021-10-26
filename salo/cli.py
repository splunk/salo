#!/usr/bin/env python3

#   Copyrigh 2021 Splunk, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from argparse import ArgumentParser
import importlib
import json
from sys import stderr

from pydantic.schema import schema

from salo import Sessions, __version__
from salo.outputs.console import ConsoleOutput
from salo.outputs.localfile import LocalFileOutput
from salo.outputs.splunkhec import SplunkOutput


def main():

    print(
        f"""
                   d8b         
                   88P         
                  d88          
 .d888b, d888b8b  888   d8888b 
 ?8b,   d8P' ?88  ?88  d8P' ?88
   `?8b 88b  ,88b  88b 88b  d88
`?888P' `?88P'`88b  88b`?8888P'

                    v{__version__}
                               
                               
""",
        file=stderr,
    )

    parser = ArgumentParser()
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(title="commands", dest="commands")
    subparsers.required = True

    recipe_parser = subparsers.add_parser(
        "recipe", help="Generate log events using a recipe"
    )
    recipe_parser.add_argument(
        "recipe_file",
        help="SALO recipe configuration file",
    )
    recipe_parser.add_argument(
        "-o",
        "--output-config",
        help="Configuration file for results",
    )
    recipe_parser.add_argument(
        "--splunk",
        default=False,
        const=SplunkOutput,
        action="store_const",
        help="Save results to Splunk. $SPLUNK_HOST and $SPLUNK_TOKEN env variables must be set!",
    )
    recipe_parser.add_argument(
        "--file",
        default=False,
        const=LocalFileOutput,
        action="store_const",
        help="Save results to local file",
    )

    schema_parser = subparsers.add_parser(
        "schema", help="Display schema for Event Model"
    )
    schema_parser.add_argument(
        "event_model",
        nargs="+",
        help="SALO Event Model path",
    )

    args = parser.parse_args()

    if args.commands == "schema":
        for event_model_path in args.event_model:
            try:
                module_name, event_name = event_model_path.rsplit(".", 1)
                event = getattr(importlib.import_module(module_name), event_name)
                print(json.dumps(schema([event], by_alias=False), indent=2))
            except ModuleNotFoundError:
                print(f"Failed to find event model {event_model_path}")

    elif args.commands == "recipe":
        outputs = [o for o in [args.splunk, args.file] if o] or [ConsoleOutput]
        print(
            f"[*] Generating synthetic events from {args.recipe_file}...", file=stderr
        )
        sessions = Sessions(args.recipe_file, outputs, args.output_config)
        sessions.save()
        print(f"[*] Generated {len(sessions)} events.", file=stderr)


if __name__ == "__main__":
    main()
