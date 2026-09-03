"""Pure, IDA-free per-(function, maturity) log aggregation counters.

Slice 3 of the unflatten-diagnostics-legibility plan demotes per-event
chatter (rule matches, fake-loop probes, deferred-modifier queue dumps) from
INFO to DEBUG. Per plan section 3.2 ("aggregate, do not rate-limit"), the
count itself is a diagnostic and must not simply be dropped: callers record
each event into one of these aggregators and flush a single INFO summary
line once per maturity boundary instead.

These classes have no IDA imports so they are unit-testable in isolation;
the IDA-dependent call sites (optimizer/unflattening rule classes) only
wire them up.

``flush()`` accepts any object exposing an ``info(msg, *args)`` method (a
stdlib/D810 logger, or a test double) rather than importing a logger type,
so this module has no dependency on ``d810.core.logging`` and callers keep
the actual ``logger.info(...)`` call site inside this module -- not inside
the exploration-tier module being aggregated for, which the ast-grep rule
``rules/no-info-logging-in-exploration-modules.yml`` forbids from calling
``logger.info`` directly.
"""

from __future__ import annotations

import dataclasses

from d810.core.typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:

    class _InfoLogger(Protocol):
        def info(self, msg: str, *args: Any) -> None: ...


@dataclasses.dataclass(slots=True)
class RuleMatchAggregator:
    """Counts rule matches by rule name within one (optimizer, maturity)."""

    counts: dict[str, int] = dataclasses.field(default_factory=dict)

    def record(self, rule_name: str) -> None:
        self.counts[rule_name] = self.counts.get(rule_name, 0) + 1

    def total(self) -> int:
        return sum(self.counts.values())

    def is_empty(self) -> bool:
        return not self.counts

    def summary_line(self) -> str:
        parts = ", ".join(
            f"{name}={count}"
            for name, count in sorted(
                self.counts.items(), key=lambda kv: (-kv[1], kv[0])
            )
        )
        return f"rule matches: {self.total()} ({parts})"

    def reset(self) -> None:
        self.counts.clear()

    def flush(self, logger: "_InfoLogger", prefix: str) -> None:
        """Emit one INFO summary line via ``logger`` and reset. No-op if empty."""
        if self.is_empty():
            return
        logger.info("%s: %s", prefix, self.summary_line())
        self.reset()


@dataclasses.dataclass(slots=True)
class FakeLoopCheckAggregator:
    """Counts fake-loop probe checks and how many were confirmed."""

    checked: int = 0
    confirmed: int = 0

    def record(self, *, confirmed: bool) -> None:
        self.checked += 1
        if confirmed:
            self.confirmed += 1

    def is_empty(self) -> bool:
        return self.checked == 0

    def summary_line(self) -> str:
        return f"fake-loop checks: {self.checked}, confirmed: {self.confirmed}"

    def reset(self) -> None:
        self.checked = 0
        self.confirmed = 0

    def flush(self, logger: "_InfoLogger", prefix: str) -> None:
        """Emit one INFO summary line via ``logger`` and reset. No-op if empty."""
        if self.is_empty():
            return
        logger.info("%s: %s", prefix, self.summary_line())
        self.reset()
