"""siemlab: tooling for the SIEM home lab.

Commands:
  validate    statically check every Wazuh, Sigma and Suricata rule in detections/
  coverage    generate (or check) docs/detection-coverage.md
  generate    write synthetic Wazuh alerts for the lab's attack scenarios
  correlate   turn a Wazuh alerts.json into incidents and incident reports
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__, alerts, correlate, generate, report, validate

log = logging.getLogger("siemlab")
SEVERITY_RANK = {s: i for i, s in enumerate(correlate.SEVERITIES)}


def cmd_validate(args: argparse.Namespace) -> int:
    cat = validate.load_catalogue(args.detections)
    for issue in cat.issues:
        print(issue)
    errors = len(cat.errors)
    warnings = len(cat.issues) - errors
    print(
        f"{len(cat.wazuh)} Wazuh rules, {len(cat.sigma)} Sigma rules, "
        f"{len(cat.suricata_sids)} Suricata signatures: {errors} error(s), {warnings} warning(s)",
        file=sys.stderr,
    )
    return 1 if errors or (args.strict and warnings) else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    text = validate.coverage_markdown(validate.load_catalogue(args.detections))
    if args.check:
        current = args.check.read_text(encoding="utf-8") if args.check.exists() else ""
        if current.replace("\r\n", "\n") != text:
            print(
                f"{args.check} is out of date: run `siemlab coverage --write {args.check}`",
                file=sys.stderr,
            )
            return 1
        print(f"{args.check} is up to date", file=sys.stderr)
    elif args.write:
        args.write.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {args.write}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    docs = generate.generate(args.detections, args.scenario or None, args.seed)
    lines = "\n".join(alerts.iter_json_lines(docs)) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(lines, encoding="utf-8", newline="\n")
        print(f"wrote {len(docs)} alerts to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(lines)
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    loaded = alerts.load(args.alerts)
    cfg = correlate.Config(
        window=timedelta(minutes=args.window),
        brute_force_threshold=args.threshold,
    )
    incidents = [
        inc
        for inc in correlate.correlate(loaded.alerts, cfg)
        if SEVERITY_RANK[inc.severity] <= SEVERITY_RANK[args.min_severity]
    ]

    if args.format == "json":
        print(
            json.dumps(
                {
                    "alerts": len(loaded.alerts),
                    "skipped_lines": loaded.skipped,
                    "incidents": [inc.to_dict() for inc in incidents],
                },
                indent=2,
            )
        )
    else:
        print(report.summary_markdown(incidents, alerts=len(loaded.alerts), skipped=loaded.skipped))

    if args.report_dir:
        args.report_dir.mkdir(parents=True, exist_ok=True)
        for inc in incidents:
            path = args.report_dir / f"{inc.id}.md"
            path.write_text(
                report.incident_markdown(inc, source=args.alerts.name),
                encoding="utf-8",
                newline="\n",
            )
        print(f"wrote {len(incidents)} incident report(s) to {args.report_dir}", file=sys.stderr)
    return 2 if args.fail_on_incident and incidents else 0


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siemlab", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="log skipped lines and progress")
    p.add_argument(
        "--detections",
        type=Path,
        default=Path("detections"),
        help="detections directory (default: ./detections)",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    v = sub.add_parser("validate", help="statically check all detection rules")
    v.add_argument("--strict", action="store_true", help="treat warnings as errors")
    v.set_defaults(func=cmd_validate)

    c = sub.add_parser("coverage", help="ATT&CK coverage matrix as Markdown")
    mode = c.add_mutually_exclusive_group()
    mode.add_argument("--write", type=Path, metavar="FILE", help="write the matrix to FILE")
    mode.add_argument("--check", type=Path, metavar="FILE", help="fail if FILE is out of date")
    c.set_defaults(func=cmd_coverage)

    g = sub.add_parser("generate", help="synthetic Wazuh alerts for the lab scenarios")
    g.add_argument(
        "--scenario",
        action="append",
        choices=list(generate.SCENARIOS),
        help="scenario to include (repeatable; default: all)",
    )
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--out", type=Path, help="output file (default: stdout)")
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("correlate", help="correlate Wazuh alerts into incidents")
    r.add_argument("alerts", type=Path, help="alerts.json (JSON lines) from the Wazuh manager")
    r.add_argument(
        "--window",
        type=_positive_int,
        default=15,
        metavar="MINUTES",
        help="correlation window (default: 15)",
    )
    r.add_argument(
        "--threshold",
        type=_positive_int,
        default=5,
        help="failures before a success counts as compromise (default: 5)",
    )
    r.add_argument("--format", choices=["markdown", "json"], default="markdown")
    r.add_argument("--min-severity", choices=correlate.SEVERITIES, default="low")
    r.add_argument("--report-dir", type=Path, help="write one Markdown report per incident")
    r.add_argument(
        "--fail-on-incident",
        action="store_true",
        help="exit with status 2 when any incident is found",
    )
    r.set_defaults(func=cmd_correlate)
    return p


def _is_console(stream: io.TextIOWrapper) -> bool:
    """A real interactive console (on Windows, NUL also claims to be a TTY)."""
    if sys.platform == "win32":
        raw = getattr(stream.buffer, "raw", None)
        return type(raw).__name__ == "_WindowsConsoleIO"
    return stream.isatty()


def _configure_streams() -> None:
    """UTF-8 for files, pipes and NUL; never crash on characters a console cannot show."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            if _is_console(stream):
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_streams()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.ERROR,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        code: int = args.func(args)
    except (OSError, ValueError) as exc:
        log.error("%s", exc)
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
