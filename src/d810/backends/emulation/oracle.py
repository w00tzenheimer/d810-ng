"""Unified emulation oracle composed from Unicorn + Triton backends."""

from __future__ import annotations

from d810.backends.emulation.common import (
    Architecture,
    BoundaryKind,
    CorridorEventKind,
    CorridorTraceResult,
    EmulationState,
    StateTransition,
)
from d810.backends.emulation.triton import TritonEmulator
from d810.backends.emulation.unicorn import UnicornEmulator


class EmulationOracle:
    """Facade combining concrete and symbolic emulation backends."""

    def __init__(self, arch: Architecture = Architecture.X86_64):
        self.arch = arch
        self._unicorn = UnicornEmulator(arch)
        self._triton = TritonEmulator(arch)

    @classmethod
    def create(cls, arch: str = "x86_64") -> "EmulationOracle":
        arch_map = {
            "x86": Architecture.X86,
            "x86_64": Architecture.X86_64,
            "x64": Architecture.X86_64,
            "arm64": Architecture.ARM64,
            "aarch64": Architecture.ARM64,
        }
        return cls(arch_map.get(arch.lower(), Architecture.X86_64))

    @property
    def has_unicorn(self) -> bool:
        return self._unicorn.available

    @property
    def has_triton(self) -> bool:
        return self._triton.available

    def reset(self) -> None:
        self._unicorn.reset()
        self._triton.reset()

    def emulate_block(
        self,
        code: bytes,
        start_addr: int = UnicornEmulator.CODE_BASE,
        initial_regs: dict[str, int] | None = None,
        initial_mem: dict[int, bytes] | None = None,
        max_instructions: int | None = None,
    ) -> EmulationState:
        return self._unicorn.emulate_block(
            code=code,
            start_addr=start_addr,
            initial_regs=initial_regs,
            initial_mem=initial_mem,
            max_instructions=max_instructions,
        )

    def trace_state_variable(
        self,
        code: bytes,
        state_var_offset: int,
        initial_state: int,
        start_addr: int = UnicornEmulator.CODE_BASE,
    ) -> list[StateTransition]:
        return self._unicorn.trace_state_variable(
            code=code,
            state_var_offset=state_var_offset,
            initial_state=initial_state,
            start_addr=start_addr,
        )

    def trace_corridor(
        self,
        code: bytes,
        *,
        code_base: int = UnicornEmulator.CODE_BASE,
        entry_addr: int = UnicornEmulator.CODE_BASE,
        state_var_offset: int | None = None,
        initial_regs: dict[str, int] | None = None,
        initial_mem: dict[int, bytes] | None = None,
        initial_stack_values: dict[int, int] | None = None,
        max_instructions: int | None = None,
        watched_stack_offsets: tuple[int, ...] = (),
    ) -> CorridorTraceResult:
        return self._unicorn.trace_corridor(
            code=code,
            code_base=code_base,
            entry_addr=entry_addr,
            state_var_offset=state_var_offset,
            initial_regs=initial_regs,
            initial_mem=initial_mem,
            initial_stack_values=initial_stack_values,
            max_instructions=max_instructions,
            watched_stack_offsets=watched_stack_offsets,
        )

    def classify_boundary(
        self,
        code: bytes,
        *,
        code_base: int = UnicornEmulator.CODE_BASE,
        entry_addr: int = UnicornEmulator.CODE_BASE,
        state_var_offset: int | None = None,
        initial_regs: dict[str, int] | None = None,
        initial_mem: dict[int, bytes] | None = None,
        initial_stack_values: dict[int, int] | None = None,
        max_instructions: int | None = None,
        watched_stack_offsets: tuple[int, ...] = (),
    ) -> BoundaryKind | None:
        """Classify a successor corridor using Unicorn-only evidence.

        This is intentionally conservative and returns None when the trace
        does not support a safe classification.
        """
        if not self.has_unicorn:
            return None
        trace = self.trace_corridor(
            code=code,
            code_base=code_base,
            entry_addr=entry_addr,
            state_var_offset=state_var_offset,
            initial_regs=initial_regs,
            initial_mem=initial_mem,
            initial_stack_values=initial_stack_values,
            max_instructions=max_instructions,
            watched_stack_offsets=watched_stack_offsets,
        )
        if not trace.events:
            return None
        saw_state_write = False
        for event in trace.events:
            if event.kind == CorridorEventKind.STATE_WRITE:
                saw_state_write = True
                continue
            if not saw_state_write:
                continue
            if event.kind == CorridorEventKind.WATCHED_STACK_WRITE:
                return BoundaryKind.UNSAFE_SIDE_EFFECT
            if event.kind == CorridorEventKind.TERMINAL:
                return BoundaryKind.TERMINAL
        if saw_state_write:
            return BoundaryKind.TRANSIENT_CORRIDOR
        return None

    def prove_branch(
        self,
        condition_ast,
        constraints: list | None = None,
    ) -> tuple[bool | None, dict]:
        return self._triton.prove_branch(condition_ast, constraints)

    def enumerate_values(
        self,
        expr_ast,
        max_values: int = 8,
    ) -> list[int] | None:
        return self._triton.enumerate_values(expr_ast, max_values)


def create_oracle(arch: str = "auto") -> EmulationOracle:
    """Create an emulation oracle, auto-detecting architecture if needed."""
    if arch == "auto":
        arch = "x86_64"
    return EmulationOracle.create(arch)
