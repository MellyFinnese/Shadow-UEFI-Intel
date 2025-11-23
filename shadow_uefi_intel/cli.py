"""Command-line interface for Shadow UEFI Intel."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .baseline import BaselineComparator, load_baseline
from .parser import FirmwareParser
from .reporting import ReportBuilder
from .triage import TriageEngine


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UEFI / firmware inspection toolkit")
    parser.add_argument("image", type=Path, help="Path to the firmware image or update package")
    parser.add_argument("--baseline", type=Path, help="Optional baseline JSON produced by this tool")
    parser.add_argument("--json", type=Path, default=Path("firmware_report.json"), help="Path to write the JSON report")
    parser.add_argument("--markdown", type=Path, default=Path("firmware_report.md"), help="Path to write the Markdown report")
    parser.add_argument("--skip-markdown", action="store_true", help="Skip writing the Markdown report")
    return parser.parse_args()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args()

    parser = FirmwareParser(args.image)
    parsed = parser.parse()

    comparison = None
    if args.baseline:
        baseline = load_baseline(args.baseline)
        comparison = BaselineComparator(parsed.inventory, baseline).compare()

    triage = TriageEngine(parsed.inventory, comparison).summarize()
    reporter = ReportBuilder(parsed.inventory)
    reporter.write_json(args.json, comparison, triage)
    if not args.skip_markdown:
        reporter.write_markdown(args.markdown, comparison, triage)

    print(f"Wrote JSON report to {args.json}")
    if not args.skip_markdown:
        print(f"Wrote Markdown report to {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
