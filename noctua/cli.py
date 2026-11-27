import argparse
import subprocess
import sys

from .engine import decide
from .nft import to_nft
from .rules import RuleError, load_rules

HEADER = "table inet noctua\ndelete table inet noctua\n"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="noctua", description="YAML rules in, nftables out."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("show", help="print the nftables ruleset, change nothing")
    show.add_argument("rules_file")

    test = sub.add_parser("test", help="see what happens to one packet")
    test.add_argument("rules_file")
    test.add_argument("--direction", choices=["in", "out"], default="in")
    test.add_argument("--proto", default="tcp")
    test.add_argument("--port", type=int)
    test.add_argument("--src", help="source address, for incoming packets")
    test.add_argument("--dst", help="destination address, for outgoing packets")

    apply_cmd = sub.add_parser("apply", help="load the rules (linux, root only)")
    apply_cmd.add_argument("rules_file")
    apply_cmd.add_argument("--yes", action="store_true", help="really do it")

    return parser


def run_nft(args, text):
    try:
        return subprocess.run(["nft", *args], input=text, text=True).returncode
    except FileNotFoundError:
        print(
            "noctua: nft not found. apply only works on Linux with nftables installed.",
            file=sys.stderr,
        )
        return 127


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        rules = load_rules(args.rules_file)
    except (RuleError, OSError) as err:
        print(f"noctua: {err}", file=sys.stderr)
        return 2

    if args.command == "show":
        print(to_nft(rules), end="")
        return 0

    if args.command == "test":
        needed = args.src if args.direction == "in" else args.dst
        if needed is None:
            flag = "--src" if args.direction == "in" else "--dst"
            print(f"noctua: {flag} is needed for {args.direction} packets", file=sys.stderr)
            return 2
        packet = {
            "direction": args.direction,
            "protocol": args.proto,
            "port": args.port,
            "source": args.src,
            "destination": args.dst,
        }
        print(decide(rules, packet))
        return 0

    if not args.yes:
        print("dry run: nothing applied. Add --yes to load these rules.")
        print(to_nft(rules), end="")
        return 0

    text = HEADER + to_nft(rules)
    check = run_nft(["-c", "-f", "-"], text)
    if check == 127:
        return 127
    if check != 0:
        print("noctua: nft rejected the ruleset, nothing was changed", file=sys.stderr)
        return 1
    return run_nft(["-f", "-"], text)