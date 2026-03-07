#!/usr/bin/env python3
"""Post-hoc gate audit tool for d810 debug logs.

Parses d810 log files and produces a gate outcome summary report.
This is a standalone script that does NOT import d810 at runtime.

Gate outcome sources in d810 logs
---------------------------------
1. Hodur executor gate accounting lines:
   ``Gate accounting: N passed, M failed, K bypassed``

2. Hodur provenance phase summaries:
   ``Provenance: N APPLIED, M GATE_FAILED, ...``

3. Flow-context gate denials:
   ``Skipping <Rule> via flow context gate: <reason>``

4. Preconditioner gate bypasses:
   ``Gate bypassed [config_disabled]: ...``

5. Maturity/max-pass gate skips (normal operation):
   ``Gate skipped [maturity_filter]: ...``
   ``Gate skipped [max_passes]: ...``

6. Safeguard gate rejections:
   ``Safeguard gate rejected stage <name>: ...``

7. Provenance detail JSON (when DEBUG logging is enabled):
   ``Provenance detail: { ... "gate_accounting": [...] ... }``

Exit codes
----------
- 0: Zero untracked bypasses found (or --strict: zero bypasses of any kind).
- 1: Untracked bypasses detected (or --strict: any bypass detected).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class GateEvent:
    """One parsed gate event from a log line."""

    source: str          # e.g. "executor", "flow_context", "preconditioner", "safeguard"
    verdict: str         # PASSED, FAILED, BYPASSED, SKIPPED
    reason: str          # human-readable reason
    line_number: int = 0
    rule_name: str = ""


@dataclass
class AuditSummary:
    """Aggregated gate audit results."""

    total: int = 0
    passed: int = 0
    failed: int = 0
    bypassed: int = 0
    skipped: int = 0
    bypass_reasons: Counter = field(default_factory=Counter)
    events: list[GateEvent] = field(default_factory=list)

    @property
    def untracked_bypasses(self) -> int:
        """Bypasses without an explicit, known reason code."""
        tracked_keys = {
            "config_disabled",
            "pipeline_abort",
            "safeguard",
            "strict_mode_disabled",
            "collect_only",
        }
        untracked = 0
        for reason, count in self.bypass_reasons.items():
            if reason not in tracked_keys:
                untracked += count
        return untracked

    def to_dict(self) -> dict:
        """Serialize to a JSON-friendly dict."""
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "bypassed": self.bypassed,
            "skipped": self.skipped,
            "bypass_reasons": dict(self.bypass_reasons),
            "untracked_bypasses": self.untracked_bypasses,
        }


# ---------------------------------------------------------------------------
# Log parsing patterns
# ---------------------------------------------------------------------------

# Pattern 1: Hodur executor gate accounting summary
# Example: "Gate accounting: 3 passed, 0 failed, 0 bypassed"
RE_GATE_ACCOUNTING = re.compile(
    r"Gate accounting:\s*"
    r"(\d+)\s+passed,\s*(\d+)\s+failed,\s*(\d+)\s+bypassed"
)

# Pattern 2: Flow-context gate denial
# Example: "Skipping FixPredecessorOfConditionalJumpBlock via flow context gate: reason"
RE_FLOW_CONTEXT_GATE = re.compile(
    r"Skipping\s+(\S+)\s+via flow context gate:\s*(.+)"
)

# Pattern 3: Preconditioner gate bypass
# Example: "Gate bypassed [config_disabled]: MbaStatePreconditioner ..."
RE_GATE_BYPASSED = re.compile(
    r"Gate bypassed\s*\[(\w+)\]:\s*(\S+)\s*(.*)"
)

# Pattern 4: Gate skipped (maturity/max_passes -- normal operation)
# Example: "Gate skipped [maturity_filter]: FixPred... at maturity 16 not in ..."
RE_GATE_SKIPPED = re.compile(
    r"Gate skipped\s*\[(\w+)\]:\s*(\S+)\s*(.*)"
)

# Pattern 5: Safeguard gate rejection
# Example: "Safeguard gate rejected stage s1: 0 passed, 1 failed, 0 bypassed"
RE_SAFEGUARD_REJECTED = re.compile(
    r"Safeguard gate rejected stage\s+(\S+):\s*"
    r"(\d+)\s+passed,\s*(\d+)\s+failed,\s*(\d+)\s+bypassed"
)

# Pattern 6: Provenance phase summary
# Example: "Provenance: 1 APPLIED, 1 CONFLICT_DROPPED, 2 INAPPLICABLE"
RE_PROVENANCE_SUMMARY = re.compile(
    r"Provenance:\s*(.+)"
)

# Sub-pattern for provenance phase items
RE_PROVENANCE_ITEM = re.compile(r"(\d+)\s+(\w+)")

# Pattern 7: Provenance detail JSON (multi-line, captured separately)
RE_PROVENANCE_DETAIL = re.compile(r"Provenance detail:\s*(\{.*)")


def _parse_provenance_detail_gate_decisions(json_str: str) -> list[GateEvent]:
    """Extract GateDecision entries from a provenance detail JSON blob."""
    events: list[GateEvent] = []
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return events
    rows = data.get("rows", [])
    for row in rows:
        acct = row.get("gate_accounting", [])
        for gd in acct:
            verdict = gd.get("verdict", "").upper()
            events.append(GateEvent(
                source="provenance_detail",
                verdict=verdict,
                reason=gd.get("reason", ""),
                rule_name=row.get("strategy_name", ""),
            ))
    return events


# ---------------------------------------------------------------------------
# Log file scanner
# ---------------------------------------------------------------------------

def scan_log_file(path: Path) -> AuditSummary:
    """Scan a single log file and return aggregated gate events."""
    summary = AuditSummary()

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            _parse_line(line, line_no, summary)

    return summary


def _parse_line(line: str, line_no: int, summary: AuditSummary) -> None:
    """Parse a single log line and update the summary."""

    # Pattern 1: Gate accounting (Hodur executor)
    m = RE_GATE_ACCOUNTING.search(line)
    if m:
        passed = int(m.group(1))
        failed = int(m.group(2))
        bypassed = int(m.group(3))
        summary.total += passed + failed + bypassed
        summary.passed += passed
        summary.failed += failed
        summary.bypassed += bypassed
        if bypassed > 0:
            # Gate accounting lines don't carry a reason code for bypasses;
            # those are "untracked" unless a provenance detail follows.
            summary.bypass_reasons["<untracked>"] += bypassed
            for _ in range(bypassed):
                summary.events.append(GateEvent(
                    source="executor",
                    verdict="BYPASSED",
                    reason="<untracked from accounting line>",
                    line_number=line_no,
                ))
        return

    # Pattern 5: Safeguard gate rejection (before flow context to avoid false match)
    m = RE_SAFEGUARD_REJECTED.search(line)
    if m:
        stage_name = m.group(1)
        passed = int(m.group(2))
        failed = int(m.group(3))
        bypassed = int(m.group(4))
        summary.total += passed + failed + bypassed
        summary.passed += passed
        summary.failed += failed
        summary.bypassed += bypassed
        if failed > 0:
            summary.events.append(GateEvent(
                source="safeguard",
                verdict="FAILED",
                reason=f"safeguard rejected stage {stage_name}",
                line_number=line_no,
                rule_name=stage_name,
            ))
        return

    # Pattern 2: Flow-context gate denial
    m = RE_FLOW_CONTEXT_GATE.search(line)
    if m:
        rule_name = m.group(1)
        reason = m.group(2).strip()
        summary.total += 1
        summary.failed += 1
        summary.events.append(GateEvent(
            source="flow_context",
            verdict="FAILED",
            reason=reason,
            line_number=line_no,
            rule_name=rule_name,
        ))
        return

    # Pattern 3: Gate bypassed (preconditioner config_disabled, etc.)
    m = RE_GATE_BYPASSED.search(line)
    if m:
        bypass_reason = m.group(1)  # e.g. "config_disabled"
        rule_name = m.group(2)
        summary.total += 1
        summary.bypassed += 1
        summary.bypass_reasons[bypass_reason] += 1
        summary.events.append(GateEvent(
            source="preconditioner",
            verdict="BYPASSED",
            reason=bypass_reason,
            line_number=line_no,
            rule_name=rule_name,
        ))
        return

    # Pattern 4: Gate skipped (maturity_filter, max_passes)
    m = RE_GATE_SKIPPED.search(line)
    if m:
        skip_reason = m.group(1)  # e.g. "maturity_filter", "max_passes"
        rule_name = m.group(2)
        summary.total += 1
        summary.skipped += 1
        summary.events.append(GateEvent(
            source="gate_skip",
            verdict="SKIPPED",
            reason=skip_reason,
            line_number=line_no,
            rule_name=rule_name,
        ))
        return

    # Pattern 6: Provenance phase summary -- extract GATE_FAILED and BYPASSED counts
    m = RE_PROVENANCE_SUMMARY.search(line)
    if m:
        body = m.group(1)
        for item_m in RE_PROVENANCE_ITEM.finditer(body):
            count = int(item_m.group(1))
            phase = item_m.group(2).upper()
            if phase == "BYPASSED":
                summary.total += count
                summary.bypassed += count
                summary.bypass_reasons["pipeline_abort"] += count
                for _ in range(count):
                    summary.events.append(GateEvent(
                        source="provenance",
                        verdict="BYPASSED",
                        reason="pipeline_abort",
                        line_number=line_no,
                    ))
        # Note: we do NOT double-count APPLIED/GATE_FAILED from provenance
        # summaries because those are already counted from executor gate
        # accounting lines. We only pull BYPASSED (pipeline tail) which
        # the executor does not emit accounting lines for.
        return


def scan_log_directory(path: Path) -> AuditSummary:
    """Scan all *.log files in a directory and merge results."""
    combined = AuditSummary()
    log_files = sorted(path.glob("*.log"))
    if not log_files:
        print(f"Warning: no *.log files found in {path}", file=sys.stderr)
        return combined

    for log_file in log_files:
        result = scan_log_file(log_file)
        combined.total += result.total
        combined.passed += result.passed
        combined.failed += result.failed
        combined.bypassed += result.bypassed
        combined.skipped += result.skipped
        combined.bypass_reasons.update(result.bypass_reasons)
        combined.events.extend(result.events)

    return combined


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_text_report(summary: AuditSummary, strict: bool = False) -> str:
    """Render a human-readable summary table."""
    lines: list[str] = []
    lines.append("Gate Audit Summary")
    lines.append("=" * 40)
    lines.append(f"  Total gates evaluated:  {summary.total}")
    lines.append(f"  Passed:                 {summary.passed}")
    lines.append(f"  Failed:                 {summary.failed}")
    lines.append(f"  Bypassed:               {summary.bypassed}")
    lines.append(f"  Skipped:                {summary.skipped}")
    lines.append("")

    if summary.bypass_reasons:
        lines.append("Bypass breakdown by reason:")
        for reason, count in sorted(summary.bypass_reasons.items()):
            marker = " (*)" if reason == "<untracked>" else ""
            lines.append(f"  {reason}: {count}{marker}")
        lines.append("")

    untracked = summary.untracked_bypasses
    lines.append(f"Untracked bypasses: {untracked}")

    if strict:
        if summary.bypassed > 0:
            lines.append(f"STRICT MODE: {summary.bypassed} bypass(es) found -- FAIL")
        else:
            lines.append("STRICT MODE: zero bypasses -- PASS")
    else:
        if untracked > 0:
            lines.append(f"Untracked bypasses found -- FAIL")
        else:
            lines.append("Zero untracked bypasses -- PASS")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="gate_audit",
        description=(
            "Parse d810 debug logs and produce a gate outcome summary report. "
            "Exit code 0 if zero untracked bypasses, 1 otherwise."
        ),
    )
    parser.add_argument(
        "log_path",
        nargs="?",
        default=str(Path.home() / ".idapro" / "logs" / "d810_logs"),
        help=(
            "Path to a log file or directory containing *.log files. "
            "Defaults to ~/.idapro/logs/d810_logs/"
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on ANY bypass, not just untracked ones.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output machine-readable JSON instead of a text table.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"Error: path does not exist: {log_path}", file=sys.stderr)
        return 1

    if log_path.is_file():
        summary = scan_log_file(log_path)
    elif log_path.is_dir():
        summary = scan_log_directory(log_path)
    else:
        print(f"Error: not a file or directory: {log_path}", file=sys.stderr)
        return 1

    if args.json_output:
        output = summary.to_dict()
        output["strict_mode"] = args.strict
        if args.strict:
            output["result"] = "FAIL" if summary.bypassed > 0 else "PASS"
        else:
            output["result"] = "FAIL" if summary.untracked_bypasses > 0 else "PASS"
        print(json.dumps(output, indent=2))
    else:
        print(render_text_report(summary, strict=args.strict))

    # Determine exit code
    if args.strict:
        return 1 if summary.bypassed > 0 else 0
    return 1 if summary.untracked_bypasses > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
