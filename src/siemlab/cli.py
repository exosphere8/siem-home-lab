"""siemlab: detection engineering toolkit for Wazuh 4 and Wazuh 5.

Commands:
  init        copy the lab kit (detections, scripts, configs, runbooks) into a directory
  demo        correlate the bundled synthetic data, to see what siemlab does
  validate    statically check every Wazuh, Sigma and Suricata rule in detections/,
              and the Wazuh 5 content pack in detections/wazuh5
  coverage    generate (or check) docs/detection-coverage.md
  generate    write synthetic Wazuh 4.x alerts or Wazuh 5 findings for the lab's scenarios
  correlate   turn Wazuh 4.x alerts or Wazuh 5 findings into incidents and incident reports
  wazuh5      Wazuh 5: fetch-schema, deploy, monitors, export, bundle

Detections come from --detections, else ./detections, else the kit installed with siemlab.
Indexer passwords are read from WAZUH_INDEXER_PASSWORD or a prompt, never from arguments.
"""

from __future__ import annotations

import argparse
import getpass
import io
import json
import logging
import os
import sys
from datetime import timedelta
from pathlib import Path

from . import (
    __version__,
    alerts,
    correlate,
    deploy5,
    export5,
    generate,
    kit,
    logtest4,
    report,
    schema,
    validate,
    wazuh5,
)
from .indexer import IndexerClient, IndexerError

log = logging.getLogger("siemlab")
SEVERITY_RANK = {s: i for i, s in enumerate(correlate.SEVERITIES)}


def _load(detections: Path) -> tuple[validate.Catalogue, wazuh5.Pack | None]:
    """The 4.x catalogue and the Wazuh 5 pack, with the pack's issues added to the catalogue."""
    cat = validate.load_catalogue(detections)
    pack = wazuh5.load_pack(detections / "wazuh5", cat.issues)
    if pack is not None:
        wazuh5.check_migration(pack, cat, cat.issues)
    return cat, pack


def _require_pack(detections: Path) -> tuple[validate.Catalogue, wazuh5.Pack]:
    cat, pack = _load(detections)
    if pack is None:
        raise FileNotFoundError(f"no Wazuh 5 content pack in {detections / 'wazuh5'}")
    if cat.errors:
        raise ValueError("the detections have errors: run `siemlab validate` first")
    return cat, pack


def cmd_init(args: argparse.Namespace) -> int:
    copied = kit.init(args.directory, force=args.force)
    print(f"Lab kit copied to {args.directory}: {', '.join(copied)}")
    print("Next:")
    print(f"  cd {args.directory}")
    print("  siemlab validate                 # checks the detections you now own")
    print("  docs/setup-guides/00-host-preparation.md  # build the lab")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    name = "findings-wazuh5-synthetic.json" if args.wazuh5 else "alerts-synthetic.json"
    args.alerts = kit.sample(name)
    return cmd_correlate(args)


def cmd_validate(args: argparse.Namespace) -> int:
    cat, pack = _load(args.detections)
    for issue in cat.issues:
        print(issue)
    errors = len(cat.errors)
    warnings = len(cat.issues) - errors
    wazuh5_count = f", {len(pack.rules)} Wazuh 5 rules" if pack else ""
    print(
        f"{len(cat.wazuh)} Wazuh rules, {len(cat.sigma)} Sigma rules, "
        f"{len(cat.suricata_sids)} Suricata signatures{wazuh5_count}: "
        f"{errors} error(s), {warnings} warning(s)",
        file=sys.stderr,
    )
    return 1 if errors or (args.strict and warnings) else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    text = validate.coverage_markdown(*_load(args.detections))
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
    kind = "alerts"
    if args.format == "wazuh5":
        cat, pack = _require_pack(args.detections)
        docs = wazuh5.findings_from_wazuh4(docs, pack, cat)
        kind = "findings"
    lines = "\n".join(alerts.iter_json_lines(docs)) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(lines, encoding="utf-8", newline="\n")
        print(f"wrote {len(docs)} {kind} to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(lines)
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    loaded = alerts.load(args.alerts)
    cfg = correlate.Config(
        window=timedelta(minutes=args.window),
        brute_force_threshold=args.threshold,
        stateful=loaded.wazuh5,  # Wazuh 5 rules cannot count events, so siemlab does
    )
    if loaded.wazuh5:
        log.info("Wazuh 5 findings: %d merged into the alert of their event", loaded.merged)
    incidents = [
        inc
        for inc in correlate.correlate(loaded.alerts, cfg)
        if SEVERITY_RANK[inc.severity] <= SEVERITY_RANK[args.min_severity]
    ]

    if args.format == "json":
        print(
            json.dumps(
                {
                    "source": "wazuh5" if loaded.wazuh5 else "wazuh4",
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


# -- wazuh5 ----------------------------------------------------------------------------------


def _password() -> str:
    """From WAZUH_INDEXER_PASSWORD, or a prompt; never from the command line."""
    password = os.environ.get("WAZUH_INDEXER_PASSWORD")
    if password:
        return password
    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass("Wazuh indexer password: ")
    raise ValueError("set WAZUH_INDEXER_PASSWORD (it is never taken as an argument)")


def _client(args: argparse.Namespace) -> IndexerClient:
    if args.url.startswith("https://") and not (args.ca or args.insecure):
        raise ValueError("give --ca (the indexer's root CA) or, for a lab only, --insecure")
    return IndexerClient(args.url, args.user, _password(), ca_file=args.ca, insecure=args.insecure)


def _say(text: str) -> None:
    print(text, file=sys.stderr)


def cmd_wazuh5_fetch_schema(args: argparse.Namespace) -> int:
    path = schema.fetch(args.source, None if args.no_verify else schema.WCS_SHA256)
    fields = schema.load() or {}
    print(f"WCS {schema.WCS_TAG}: {len(fields)} fields saved to {path}", file=sys.stderr)
    return 0


def cmd_wazuh5_bundle(args: argparse.Namespace) -> int:
    _, pack = _require_pack(args.detections)
    written = wazuh5.bundle(pack, args.out)
    print(
        f"wrote {len(written)} file(s) for {len(pack.integrations)} integrations and "
        f"{len(pack.rules)} rules to {args.out}",
        file=sys.stderr,
    )
    return 0


def cmd_wazuh5_deploy(args: argparse.Namespace) -> int:
    _, pack = _require_pack(args.detections)
    if args.dry_run:
        for integ in pack.integrations:
            rules = [r.title for r in pack.rules if r.integration == integ.title]
            print(f"{integ.title} ({integ.category}): {len(rules)} rule(s)")
            for title in rules:
                print(f"  {title}")
        print(f"{len(pack.logtests)} logtest case(s) would run in the test space")
        return 0
    result = deploy5.deploy(pack, _client(args), promote_custom=args.promote_custom, say=_say)
    passed = len(result.logtests) - len(result.failed)
    print(f"logtest: {passed}/{len(result.logtests)} case(s) passed")
    for r in result.failed:
        print(f"FAIL {r.case.integration}: {r.case.event}")
        print(f"     expected {sorted(r.case.expect)}, matched {sorted(r.matched)}")
        if r.error:
            print(f"     {r.error}")
    if result.failed:
        print("Not promoted to custom. Fix the rules in the draft space, or adjust them here.")
        return 1
    if not result.promoted_to_custom:
        print("All cases passed. Run again with --promote-custom to put the rules in production.")
    return 0


def cmd_wazuh5_monitors(args: argparse.Namespace) -> int:
    _, pack = _require_pack(args.detections)
    if args.dry_run:
        for m in pack.monitors:
            print(f"{m.name}  (tags: {', '.join(m.tags)})")
        return 0
    ids = deploy5.deploy_monitors(pack, _client(args), say=_say)
    print(f"{len(ids)} monitor(s) in place")
    return 0


def cmd_wazuh5_export(args: argparse.Namespace) -> int:
    client = _client(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as out:
        count = export5.export_findings(client, out, since=args.since, index=args.index)
    print(f"wrote {count} finding(s) to {args.out}", file=sys.stderr)
    return 0


def cmd_wazuh4_logtest(args: argparse.Namespace) -> int:
    cases = logtest4.load_cases(args.cases or args.detections / "logtest" / "wazuh4.yml")
    results = logtest4.run_all(logtest4.socket_call(args.socket), cases, args.queue, args.alerts)
    for result in results:
        print(logtest4.describe(result))
    failed = sum(not r.passed for r in results)
    print(f"{len(results) - failed}/{len(results)} case(s) passed")
    return 1 if failed else 0


# -- parser ----------------------------------------------------------------------------------


def _positive_int(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _add_correlate_options(r: argparse.ArgumentParser) -> None:
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


def _add_connection(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--url",
        default="https://127.0.0.1:9200",
        help="Wazuh indexer URL (default: https://127.0.0.1:9200)",
    )
    parser.add_argument("--user", default="admin", help="indexer user (default: admin)")
    parser.add_argument("--ca", type=Path, metavar="FILE", help="CA certificate of the indexer")
    parser.add_argument(
        "--insecure", action="store_true", help="skip TLS verification (lab only, never prod)"
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="siemlab", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="log skipped lines and progress")
    p.add_argument(
        "--detections",
        type=Path,
        default=None,
        help="detections directory (default: ./detections, else the installed kit)",
    )
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    i = sub.add_parser("init", help="copy the lab kit into a directory of your own")
    i.add_argument("directory", type=Path, help="where to create the kit")
    i.add_argument("--force", action="store_true", help="copy into a non-empty directory")
    i.set_defaults(func=cmd_init)

    dm = sub.add_parser("demo", help="correlate the bundled synthetic data")
    dm.add_argument("--wazuh5", action="store_true", help="use the Wazuh 5 findings sample")
    _add_correlate_options(dm)
    dm.set_defaults(func=cmd_demo)

    v = sub.add_parser("validate", help="statically check all detection rules")
    v.add_argument("--strict", action="store_true", help="treat warnings as errors")
    v.set_defaults(func=cmd_validate)

    c = sub.add_parser("coverage", help="ATT&CK coverage matrix as Markdown")
    mode = c.add_mutually_exclusive_group()
    mode.add_argument("--write", type=Path, metavar="FILE", help="write the matrix to FILE")
    mode.add_argument("--check", type=Path, metavar="FILE", help="fail if FILE is out of date")
    c.set_defaults(func=cmd_coverage)

    g = sub.add_parser("generate", help="synthetic Wazuh alerts or findings for the scenarios")
    g.add_argument(
        "--scenario",
        action="append",
        choices=list(generate.SCENARIOS),
        help="scenario to include (repeatable; default: all)",
    )
    g.add_argument("--seed", type=int, default=7)
    g.add_argument(
        "--format",
        choices=["wazuh4", "wazuh5"],
        default="wazuh4",
        help="4.x alerts.json lines, or the findings the Wazuh 5 pack would write",
    )
    g.add_argument("--out", type=Path, help="output file (default: stdout)")
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("correlate", help="correlate Wazuh alerts or findings into incidents")
    r.add_argument(
        "alerts",
        type=Path,
        help="JSON lines: 4.x alerts.json, or Wazuh 5 findings (detected automatically)",
    )
    _add_correlate_options(r)
    r.set_defaults(func=cmd_correlate)

    w4 = sub.add_parser("wazuh4", help="Wazuh 4 tools")
    w4_sub = w4.add_subparsers(dest="wazuh4_command", required=True, metavar="ACTION")
    lt = w4_sub.add_parser("logtest", help="run the logtest cases on a manager (as root)")
    lt.add_argument(
        "--cases", type=Path, help="cases file (default: detections/logtest/wazuh4.yml)"
    )
    lt.add_argument("--socket", default=logtest4.DEFAULT_SOCKET, help="logtest socket path")
    lt.add_argument("--queue", default=logtest4.DEFAULT_QUEUE, help="analysis queue socket")
    lt.add_argument("--alerts", default=logtest4.DEFAULT_ALERTS, help="alerts.json path")
    lt.set_defaults(func=cmd_wazuh4_logtest)

    w = sub.add_parser("wazuh5", help="Wazuh 5 content pack tools")
    w_sub = w.add_subparsers(dest="wazuh5_command", required=True, metavar="ACTION")

    fs = w_sub.add_parser("fetch-schema", help="download the WCS field list the validator uses")
    fs.add_argument(
        "--from",
        dest="source",
        default=schema.WCS_URL,
        metavar="URL_OR_FILE",
        help="where to read fields.csv (default: wazuh-indexer-plugins at the pinned tag)",
    )
    fs.add_argument("--no-verify", action="store_true", help="skip the pinned SHA-256 check")
    fs.set_defaults(func=cmd_wazuh5_fetch_schema)

    d = w_sub.add_parser(
        "deploy", help="create the pack in the draft space, promote to test, and logtest it"
    )
    _add_connection(d)
    d.add_argument(
        "--promote-custom",
        action="store_true",
        help="promote test -> custom (production) when every logtest case passes",
    )
    d.add_argument("--dry-run", action="store_true", help="list what would be created")
    d.set_defaults(func=cmd_wazuh5_deploy)

    mo = w_sub.add_parser("monitors", help="create or update the real-time counting monitors")
    _add_connection(mo)
    mo.add_argument("--dry-run", action="store_true", help="list the monitors")
    mo.set_defaults(func=cmd_wazuh5_monitors)

    ex = w_sub.add_parser("export", help="export findings as JSON lines for `correlate`")
    _add_connection(ex)
    ex.add_argument(
        "--out",
        type=Path,
        default=Path("exports/findings.json"),
        help="output file (default: exports/findings.json; keep it out of Git)",
    )
    ex.add_argument("--since", metavar="AGE", help="only findings newer than AGE, e.g. 24h or 7d")
    ex.add_argument("--index", default=export5.FINDINGS, help="index pattern to export")
    ex.set_defaults(func=cmd_wazuh5_export)

    b = w_sub.add_parser("bundle", help="write the Content Manager API request bodies")
    b.add_argument("--out", type=Path, required=True, metavar="DIR", help="output directory")
    b.set_defaults(func=cmd_wazuh5_bundle)
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
    if args.detections is None:
        args.detections = kit.detections_dir()
    _configure_streams()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.ERROR,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        code: int = args.func(args)
    except (OSError, ValueError, IndexerError, schema.SchemaError) as exc:
        log.error("%s", exc)
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
