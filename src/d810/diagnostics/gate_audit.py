"""Post-hoc gate audit -- parses ``d810.log`` for gate outcome events.

Reads structured gate-decision lines emitted by the Hodur executor,
preconditioner, flow-context filter, and safeguard layer, and produces a
summary table + per-event breakdown. The recognised sources are:

1. Hodur executor gate accounting lines:
   ``Gate accounting: N passed, M failed, K bypassed``

2. Hodur provenance phase summaries:
   ``Provenance: N APPLIED, M GATE_FAILED, K BYPASSED, ...``

3. Flow-context gate denials:
   ``Skipping <Rule> via flow context gate: <reason>``

4. Preconditioner gate bypasses:
   ``Gate bypassed [config_disabled]: ...``

5. Maturity / max-pass gate skips (normal operation):
   ``Gate skipped [maturity_filter]: ...``
   ``Gate skipped [max_passes]: ...``

6. Safeguard gate rejections:
   ``Safeguard gate rejected stage <name>: N passed, M failed, K bypassed``

7. Provenance detail JSON (DEBUG logging only):
   ``Provenance detail: { ... "gate_accounting": [...] ... }``

The module is pure Python with no d810 runtime imports, so it works as a
``d810.diagnostics`` subcommand and as a unit-testable parser. Use
``run_audit()`` for the orchestrator + report, or call ``scan_log_file`` /
``scan_log_directory`` directly to consume the structured ``AuditSummary``.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


# Reason codes considered "tracked" -- bypasses tagged with one of these are
# expected operational outcomes; anything else is flagged as "untracked".
TRACKED_BYPASS_REASONS: frozenset[str] = frozenset(
    {
        "config_disabled",
        "pipeline_abort",
        "safeguard",
        "strict_mode_disabled",
        "collect_only",
    }
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class GateEvent:
    """One parsed gate event from a log line."""

    source: str          # executor / flow_context / preconditioner / safeguard / ...
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
        return sum(
            count
            for reason, count in self.bypass_reasons.items()
            if reason not in TRACKED_BYPASS_REASONS
        )

    def to_dict(self) -> dict:
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


# 1. Gate accounting summary
RE_GATE_ACCOUNTING = re.compile(
    r"Gate accounting:\s*"
    r"(\d+)\s+passed,\s*(\d+)\s+failed,\s*(\d+)\s+bypassed"
)
# 2. Flow-context gate denial
RE_FLOW_CONTEXT_GATE = re.compile(
    r"Skipping\s+(\S+)\s+via flow context gate:\s*(.+)"
)
# 3. Preconditioner gate bypass
RE_GATE_BYPASSED = re.compile(
    r"Gate bypassed\s*\[(\w+)\]:\s*(\S+)\s*(.*)"
)
# 4. Gate skipped (maturity_filter / max_passes)
RE_GATE_SKIPPED = re.compile(
    r"Gate skipped\s*\[(\w+)\]:\s*(\S+)\s*(.*)"
)
# 5. Safeguard gate rejection
RE_SAFEGUARD_REJECTED = re.compile(
    r"Safeguard gate rejected stage\s+(\S+):\s*"
    r"(\d+)\s+passed,\s*(\d+)\s+failed,\s*(\d+)\s+bypassed"
)
# 6. Provenance phase summary
RE_PROVENANCE_SUMMARY = re.compile(r"Provenance:\s*(.+)")
RE_PROVENANCE_ITEM = re.compile(r"(\d+)\s+(\w+)")
# 7. Provenance detail JSON (DEBUG)
RE_PROVENANCE_DETAIL = re.compile(r"Provenance detail:\s*(\{.*)")


def _parse_provenance_detail_gate_decisions(json_str: str) -> list[GateEvent]:
    """Extract ``GateDecision`` entries from a provenance detail JSON blob."""
    events: list[GateEvent] = []
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return events
    for row in data.get("rows", []) or []:
        acct = row.get("gate_accounting", []) or []
        for gd in acct:
            verdict = str(gd.get("verdict", "")).upper()
            events.append(
                GateEvent(
                    source="provenance_detail",
                    verdict=verdict,
                    reason=str(gd.get("reason", "")),
                    rule_name=str(row.get("strategy_name", "")),
                )
            )
    return events


# ---------------------------------------------------------------------------
# Log scanners
# ---------------------------------------------------------------------------


def parse_line(line: str, line_no: int, summary: AuditSummary) -> None:
    """Parse a single log line and update *summary* in-place.

    Lines that match none of the gate-related patterns are silently skipped.
    """
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
            # Accounting lines carry no reason; tag them as untracked.
            summary.bypass_reasons["<untracked>"] += bypassed
            for _ in range(bypassed):
                summary.events.append(
                    GateEvent(
                        source="executor",
                        verdict="BYPASSED",
                        reason="<untracked from accounting line>",
                        line_number=line_no,
                    )
                )
        return

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
            summary.events.append(
                GateEvent(
                    source="safeguard",
                    verdict="FAILED",
                    reason=f"safeguard rejected stage {stage_name}",
                    line_number=line_no,
                    rule_name=stage_name,
                )
            )
        return

    m = RE_FLOW_CONTEXT_GATE.search(line)
    if m:
        summary.total += 1
        summary.failed += 1
        summary.events.append(
            GateEvent(
                source="flow_context",
                verdict="FAILED",
                reason=m.group(2).strip(),
                line_number=line_no,
                rule_name=m.group(1),
            )
        )
        return

    m = RE_GATE_BYPASSED.search(line)
    if m:
        bypass_reason = m.group(1)
        summary.total += 1
        summary.bypassed += 1
        summary.bypass_reasons[bypass_reason] += 1
        summary.events.append(
            GateEvent(
                source="preconditioner",
                verdict="BYPASSED",
                reason=bypass_reason,
                line_number=line_no,
                rule_name=m.group(2),
            )
        )
        return

    m = RE_GATE_SKIPPED.search(line)
    if m:
        summary.total += 1
        summary.skipped += 1
        summary.events.append(
            GateEvent(
                source="gate_skip",
                verdict="SKIPPED",
                reason=m.group(1),
                line_number=line_no,
                rule_name=m.group(2),
            )
        )
        return

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
                    summary.events.append(
                        GateEvent(
                            source="provenance",
                            verdict="BYPASSED",
                            reason="pipeline_abort",
                            line_number=line_no,
                        )
                    )
        # APPLIED / GATE_FAILED are already counted from executor accounting.
        return


def scan_log_file(path: Path) -> AuditSummary:
    """Scan one log file and return an :class:`AuditSummary`."""
    summary = AuditSummary()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            parse_line(line, line_no, summary)
    return summary


def scan_log_directory(path: Path) -> AuditSummary:
    """Merge all ``*.log`` files in *path* into one :class:`AuditSummary`.

    Returns an empty summary if no log files are present.
    """
    combined = AuditSummary()
    log_files = sorted(path.glob("*.log"))
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


def render_text_report(summary: AuditSummary, *, strict: bool = False) -> str:
    """Human-readable summary table.

    Strict mode flips the verdict to FAIL when ANY bypass exists (not just
    untracked ones), and labels that decision in the trailing line.
    """
    lines: list[str] = [
        "Gate Audit Summary",
        "=" * 40,
        f"  Total gates evaluated:  {summary.total}",
        f"  Passed:                 {summary.passed}",
        f"  Failed:                 {summary.failed}",
        f"  Bypassed:               {summary.bypassed}",
        f"  Skipped:                {summary.skipped}",
        "",
    ]
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
            lines.append(
                f"STRICT MODE: {summary.bypassed} bypass(es) found -- FAIL"
            )
        else:
            lines.append("STRICT MODE: zero bypasses -- PASS")
    else:
        if untracked > 0:
            lines.append("Untracked bypasses found -- FAIL")
        else:
            lines.append("Zero untracked bypasses -- PASS")
    return "\n".join(lines)


def summary_exit_code(summary: AuditSummary, *, strict: bool = False) -> int:
    """Return the conventional CLI exit code (0 = PASS, 1 = FAIL)."""
    if strict:
        return 1 if summary.bypassed > 0 else 0
    return 1 if summary.untracked_bypasses > 0 else 0


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def scan_path(path: Path) -> AuditSummary:
    """Scan a file or directory, returning a single :class:`AuditSummary`."""
    if path.is_file():
        return scan_log_file(path)
    return scan_log_directory(path)


def run_audit(
    log_path: Path,
    *,
    strict: bool = False,
    as_json: bool = False,
) -> tuple[str, int]:
    """Render the gate-audit report for *log_path* and return (text, exit_code).

    *log_path* may be a single log file or a directory containing ``*.log``.
    Missing paths are reported via a one-line message and an exit code of 1.
    """
    if not log_path.exists():
        return (f"Error: path does not exist: {log_path}\n", 1)
    summary = scan_path(log_path)
    rc = summary_exit_code(summary, strict=strict)
    if as_json:
        payload = summary.to_dict()
        payload["strict_mode"] = strict
        payload["result"] = "FAIL" if rc != 0 else "PASS"
        return (json.dumps(payload, indent=2) + "\n", rc)
    return (render_text_report(summary, strict=strict) + "\n", rc)
