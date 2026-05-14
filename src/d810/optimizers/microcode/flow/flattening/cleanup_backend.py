"""Backend boundary for live non-Hodur cleanup candidate collection."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.typing import Protocol
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FakeJumpPredFix,
    collect_live_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SingleIterationPredFix,
    collect_live_single_iteration_fixes,
)

__all__ = [
    "LiveSimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupDetection",
]


@dataclass(frozen=True)
class SimpleFlatteningCleanupDetection:
    """Live cleanup candidates collected before snapshot construction."""

    fake_jump_fixes: tuple[FakeJumpPredFix, ...] = ()
    single_iteration_fixes: tuple[SingleIterationPredFix, ...] = ()
    collection_errors: tuple[str, ...] = ()
    maturity: int = 0
    func_ea: int = 0

    @property
    def detected(self) -> bool:
        return bool(self.fake_jump_fixes or self.single_iteration_fixes)

    @property
    def description(self) -> str:
        if not self.detected:
            return "no simple cleanup candidates detected"
        return (
            "simple cleanup candidates detected: "
            f"fake_jump={len(self.fake_jump_fixes)} "
            f"single_iteration={len(self.single_iteration_fixes)}"
        )


class SimpleFlatteningCleanupBackend(Protocol):
    """Collector boundary consumed by the generic cleanup family."""

    def collect(
        self,
        mba: object,
        *,
        logger: object | None = None,
    ) -> SimpleFlatteningCleanupDetection:
        """Return live cleanup candidates for one MBA."""
        ...


class LiveSimpleFlatteningCleanupBackend:
    """Default IDA-backed collector for simple cleanup evidence."""

    def __init__(
        self,
        *,
        fake_jump_max_nb_block: int = 100,
        fake_jump_max_path: int = 100,
        allowed_maturities: tuple[int, ...] = (ida_hexrays.MMAT_GLBOPT1,),
    ) -> None:
        self.fake_jump_max_nb_block = int(fake_jump_max_nb_block)
        self.fake_jump_max_path = int(fake_jump_max_path)
        self.allowed_maturities = tuple(int(maturity) for maturity in allowed_maturities)

    def collect(
        self,
        mba: object,
        *,
        logger: object | None = None,
    ) -> SimpleFlatteningCleanupDetection:
        maturity = int(getattr(mba, "maturity", 0) or 0)
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        errors: list[str] = []

        fake_jump_fixes: tuple[FakeJumpPredFix, ...] = ()
        try:
            fake_jump_fixes = collect_live_fake_jump_fixes(
                mba,
                logger=logger,
                max_nb_block=self.fake_jump_max_nb_block,
                max_path=self.fake_jump_max_path,
                allowed_maturities=self.allowed_maturities,
            )
        except Exception as exc:
            errors.append(f"fake_jump:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect FakeJump cleanup candidates",
                    exc_info=True,
                )

        single_iteration_fixes: tuple[SingleIterationPredFix, ...] = ()
        try:
            single_iteration_fixes = collect_live_single_iteration_fixes(
                mba,
                logger=logger,
                allowed_maturities=self.allowed_maturities,
            )
        except Exception as exc:
            errors.append(f"single_iteration:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect single-iteration cleanup candidates",
                    exc_info=True,
                )

        return SimpleFlatteningCleanupDetection(
            fake_jump_fixes=tuple(fake_jump_fixes),
            single_iteration_fixes=tuple(single_iteration_fixes),
            collection_errors=tuple(errors),
            maturity=maturity,
            func_ea=func_ea,
        )
