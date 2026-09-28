from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.bootstrap import build_service
from app.core.exceptions import NexhostError
from app.reports.export import export_csv, export_json
from app.reports.service import ReportService
from app.services.demo import load_demo_data
from app.services.posture import PostureService


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="nexhost-hsa", description="Authorized Host Security Auditor")
    root.add_argument("--config", type=Path)
    root.add_argument("--verbose", action="store_true")
    commands = root.add_subparsers(dest="command")
    scan = commands.add_parser("scan", help="Run an authorized Nmap audit")
    scan.add_argument("target")
    scan.add_argument("--scope", required=True)
    scan.add_argument("--profile", choices=["quick", "standard", "deep", "compliance"], default="quick")
    scan.add_argument("--authorized", action="store_true", help="Confirm you are authorized to scan the target")
    commands.add_parser("assets")
    commands.add_parser("findings")
    commands.add_parser("services")
    commands.add_parser("vulnerabilities")
    compliance = commands.add_parser("compliance")
    compliance.add_argument("--scan", type=int)
    commands.add_parser("summary")
    commands.add_parser("demo")
    import_cmd = commands.add_parser("import-xml")
    import_cmd.add_argument("path", type=Path)
    export = commands.add_parser("export")
    export.add_argument("format", choices=["json", "csv"])
    export.add_argument("destination", type=Path)
    export.add_argument("--dataset", choices=["assets", "findings"], default="findings")
    report = commands.add_parser("report")
    report.add_argument("--scan", type=int)
    report.add_argument("--format", choices=["html", "pdf", "json"], default="html")
    report.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("previous", type=int)
    compare.add_argument("current", type=int)
    commands.add_parser("gui")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.command:
        args.command = "gui"
    if args.command == "gui":
        from app.main import main as gui_main
        return gui_main()
    try:
        service = build_service(args.config, args.verbose)
        if args.command == "scan":
            print(json.dumps({"scan_id": service.run_scan(args.target, args.scope, args.profile, args.authorized)}))
        elif args.command == "assets":
            print(json.dumps(service.assets(), indent=2))
        elif args.command == "findings":
            print(json.dumps(service.findings(), indent=2))
        elif args.command == "services":
            print(json.dumps(service.services(), indent=2))
        elif args.command == "vulnerabilities":
            print(json.dumps(service.vulnerabilities(), indent=2))
        elif args.command == "compliance":
            print(json.dumps(service.compliance(args.scan), indent=2))
        elif args.command == "summary":
            print(json.dumps(service.summary(), indent=2))
        elif args.command == "demo":
            print(json.dumps(load_demo_data(service.database), indent=2))
        elif args.command == "import-xml":
            print(json.dumps({"scan_id": service.import_xml(args.path)}))
        elif args.command == "export":
            path = export_json(service, args.destination) if args.format == "json" else export_csv(service, args.destination, args.dataset)
            print(path)
        elif args.command == "report":
            print(ReportService(service).generate(args.output, args.format, args.scan))
        elif args.command == "compare":
            changes = PostureService(service.database).compare_scans(args.previous, args.current)
            print(json.dumps({key: [{"kind": c.kind, "value": c.value} for c in value] for key, value in changes.items()}, indent=2))
        return 0
    except (NexhostError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
