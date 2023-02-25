"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyze import Options, PolicyError, check_policy, load_policies, severity_at_least
from .report import render_json, render_text, summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gcp-iam-explain",
        description="Explain Google Cloud IAM allow policies (gcloud ... get-iam-policy --format=json) "
                    "and flag risky bindings. Works offline on files or stdin.",
    )
    p.add_argument("files", nargs="*", default=["-"], help="policy JSON files, or - for stdin (default)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--allowed-domains", default="",
                   help="comma-separated domains; members outside them are flagged (subdomains count)")
    p.add_argument("--max-admins", type=int, default=3,
                   help="flag admin-level roles held by more than N principals (default 3)")
    p.add_argument("--ignore", action="append", default=[], metavar="CODE",
                   help="skip a finding code, e.g. --ignore DELETED_MEMBER (repeatable)")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default high)")
    p.add_argument("--findings-only", action="store_true", help="text output: skip the per-binding explanation")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    opts = Options(
        allowed_domains={d.strip().lower() for d in args.allowed_domains.split(",") if d.strip()},
        max_admins=args.max_admins,
        ignore={c.strip().upper() for c in args.ignore},
    )
    policies = []
    try:
        for path in args.files:
            if path == "-":
                text, name = sys.stdin.read(), "<stdin>"
            else:
                with open(path, encoding="utf-8") as fh:
                    text, name = fh.read(), path
            policies.extend(load_policies(text, name))
    except (OSError, PolicyError) as exc:
        print(f"gcp-iam-explain: error: {exc}", file=sys.stderr)
        return 2

    all_findings = []
    blocks = []
    for pol in policies:
        fs = check_policy(pol, opts)
        all_findings.extend(fs)
        if args.format == "text":
            blocks.append(render_text(pol, fs, explain=not args.findings_only))
    if args.format == "json":
        print(render_json(policies, all_findings))
    else:
        print("\n\n".join(blocks))
        if len(policies) > 1:
            s = summary(all_findings)
            print("\nTotal: " + ", ".join(f"{v} {k}" for k, v in s.items()))
    if args.fail_on != "never" and any(severity_at_least(f.severity, args.fail_on) for f in all_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
