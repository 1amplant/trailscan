from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import NoCredentialsError, NoRegionError, ProfileNotFound

from trailscan import __version__
from trailscan.engine.runner import run_checks, score
from trailscan.output.terminal import print_header, print_findings, print_score
from trailscan.output.exporters import export_json, export_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trailscan",
        description="SOC 2 AWS readiness scanner — point-in-time check of your AWS environment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  trailscan                          # use default AWS profile\n"
            "  trailscan --profile staging        # named profile\n"
            "  trailscan --output json            # print JSON to stdout\n"
            "  trailscan --output json --output-file report.json\n"
            "  trailscan --output csv  --output-file report.csv\n"
            "  trailscan --checks iam.mfa_enabled_root s3.public_access_block\n"
            "\n"
            "trailscan is a point-in-time snapshot.\n"
            "For continuous monitoring, audit-ready reports, and multi-source evidence:\n"
            "  → https://trailproof.app\n"
        ),
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"trailscan {__version__}",
    )
    parser.add_argument(
        "--profile", "-p",
        metavar="PROFILE",
        default=None,
        help="AWS named profile to use (default: AWS_PROFILE env var or 'default').",
    )
    parser.add_argument(
        "--region", "-r",
        metavar="REGION",
        default=None,
        help="AWS region for regional checks (default: profile/env default).",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["terminal", "json", "csv"],
        default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument(
        "--output-file", "-f",
        metavar="FILE",
        default=None,
        help="File path for --output json/csv. Prints to stdout if omitted.",
    )
    parser.add_argument(
        "--checks",
        nargs="+",
        metavar="CHECK_ID",
        default=None,
        help="Run only the specified check IDs (space-separated).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Show evidence details for each finding.",
    )
    parser.add_argument(
        "--failed-only",
        action="store_true",
        default=False,
        help="Only show FAIL findings in terminal output.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ── Build boto3 session ────────────────────────────────────────────────────
    kwargs: dict = {}
    if args.profile:
        kwargs["profile_name"] = args.profile
    if args.region:
        kwargs["region_name"] = args.region

    try:
        session = boto3.Session(**kwargs)
        # Verify credentials exist before running checks
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
    except ProfileNotFound:
        print(f"Error: AWS profile '{args.profile}' not found.", file=sys.stderr)
        sys.exit(1)
    except NoCredentialsError:
        print(
            "Error: No AWS credentials found.\n"
            "Configure via: aws configure, AWS_ACCESS_KEY_ID env vars, or --profile.",
            file=sys.stderr,
        )
        sys.exit(1)
    except NoRegionError:
        print(
            "Error: No AWS region set.\n"
            "Use --region, set AWS_DEFAULT_REGION, or configure a default region.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"Error connecting to AWS: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Print header (terminal mode only) ─────────────────────────────────────
    if args.output == "terminal":
        print_header(args.profile, args.region or session.region_name)
        print(f"  Account: {account_id}")
        print("  Running checks...\n")

    # ── Run checks ─────────────────────────────────────────────────────────────
    findings = run_checks(session, check_ids=args.checks)

    # ── Output ─────────────────────────────────────────────────────────────────
    if args.output == "json":
        export_json(findings, path=args.output_file)

    elif args.output == "csv":
        export_csv(findings, path=args.output_file)

    else:
        # Terminal output
        display = findings
        if args.failed_only:
            from trailscan.engine.models import Status
            display = [f for f in findings if f.status == Status.FAIL]

        print_findings(display, verbose=args.verbose)
        print_score(score(findings))

    # Exit with non-zero if any FAIL findings exist
    from trailscan.engine.models import Status
    if any(f.status == Status.FAIL for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
