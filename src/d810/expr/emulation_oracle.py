"""
Emulation Oracle for Dispatcher Detection and Unflattening

This module provides concrete (Unicorn) and symbolic (Triton) execution
capabilities for resolving state machine transitions in obfuscated code.

Usage:
    oracle = EmulationOracle.create(arch="x86_64")

    # Concrete execution with Unicorn
    if oracle.has_unicorn:
        result = oracle.emulate_block(code_bytes, start_addr, initial_state)

    # Symbolic execution with Triton (when available)
    if oracle.has_triton:
        targets = oracle.enumerate_state_transitions(micro_slice, state_var)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

# Optional imports - gracefully degrade if not available
try:
    from unicorn import (
        UC_ARCH_ARM64,
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_UNMAPPED,
        UC_HOOK_MEM_WRITE,
        UC_MEM_READ,
        UC_MEM_WRITE,
        UC_MODE_32,
        UC_MODE_64,
        UC_MODE_ARM,
    )
    from unicorn.unicorn import Uc
    from unicorn.x86_const import (
        UC_X86_REG_EAX,
        UC_X86_REG_EBP,
        UC_X86_REG_EBX,
        UC_X86_REG_ECX,
        UC_X86_REG_EDI,
        UC_X86_REG_EDX,
        UC_X86_REG_EFLAGS,
        UC_X86_REG_EIP,
        UC_X86_REG_ESI,
        UC_X86_REG_ESP,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
        UC_X86_REG_RAX,
        UC_X86_REG_RBP,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )

    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False
    Uc = None

try:
    from triton import ARCH as TRITON_ARCH
    from triton import AST_REPRESENTATION, CPUSIZE
    from triton import Instruction as TritonInstruction
    from triton import MemoryAccess, TritonContext

    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False
    TritonContext = None

from d810.core import getLogger

logger = getLogger("D810.emulation")


class Architecture(Enum):
    """Supported architectures for emulation."""

    X86 = "x86"
    X86_64 = "x86_64"
    ARM64 = "arm64"


@dataclass
class EmulationState:
    """State snapshot from emulation."""

    registers: dict[str, int] = field(default_factory=dict)
    memory: dict[int, bytes] = field(default_factory=dict)
    flags: int = 0
    pc: int = 0
    stopped: bool = False
    stop_reason: str = ""


@dataclass
class StateTransition:
    """Represents a state machine transition discovered through emulation."""

    from_value: int
    to_value: int
    from_block: int | None = None
    to_block: int | None = None
    condition: str | None = None  # Human-readable condition
    is_proven: bool = False  # True if symbolically proven


class EmulationOracle:
    """
    Oracle for concrete and symbolic execution of code snippets.

    Supports:
    - Unicorn for concrete execution (tracing state transitions)
    - Triton for symbolic execution (proving/enumerating state values)
    """

    # Memory layout for emulation
    CODE_BASE = 0x10000
    STACK_BASE = 0x80000
    STACK_SIZE = 0x10000
    HEAP_BASE = 0x100000
    HEAP_SIZE = 0x10000

    # Execution limits
    MAX_INSTRUCTIONS = 1000
    TIMEOUT_MS = 100

    def __init__(self, arch: Architecture = Architecture.X86_64):
        self.arch = arch
        self._uc: Uc | None = None
        self._triton: TritonContext | None = None
        self._instruction_count = 0
        self._memory_accesses: list[tuple[int, int, bool]] = (
            []
        )  # (addr, size, is_write)

        self._init_unicorn()
        self._init_triton()

    @classmethod
    def create(cls, arch: str = "x86_64") -> "EmulationOracle":
        """Factory method to create oracle with specified architecture."""
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
        """True if Unicorn is available and initialized."""
        return self._uc is not None

    @property
    def has_triton(self) -> bool:
        """True if Triton is available and initialized."""
        return self._triton is not None

    def _init_unicorn(self) -> None:
        """Initialize Unicorn emulator."""
        if not UNICORN_AVAILABLE:
            logger.debug("Unicorn not available")
            return

        try:
            if self.arch == Architecture.X86_64:
                self._uc = Uc(UC_ARCH_X86, UC_MODE_64)
            elif self.arch == Architecture.X86:
                self._uc = Uc(UC_ARCH_X86, UC_MODE_32)
            elif self.arch == Architecture.ARM64:
                self._uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            else:
                logger.warning("Unsupported architecture for Unicorn: %s", self.arch)
                return

            # Map memory regions
            self._uc.mem_map(self.CODE_BASE, 0x10000)  # Code
            self._uc.mem_map(self.STACK_BASE, self.STACK_SIZE)  # Stack
            self._uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE)  # Heap

            # Set up stack pointer
            if self.arch in (Architecture.X86_64, Architecture.X86):
                sp_reg = (
                    UC_X86_REG_RSP
                    if self.arch == Architecture.X86_64
                    else UC_X86_REG_ESP
                )
                self._uc.reg_write(sp_reg, self.STACK_BASE + self.STACK_SIZE - 0x1000)

            logger.debug("Unicorn initialized for %s", self.arch.value)

        except Exception as e:
            logger.warning("Failed to initialize Unicorn: %s", e)
            self._uc = None

    def _init_triton(self) -> None:
        """Initialize Triton symbolic execution engine."""
        if not TRITON_AVAILABLE:
            logger.debug("Triton not available")
            return

        try:
            self._triton = TritonContext()

            if self.arch == Architecture.X86_64:
                self._triton.setArchitecture(TRITON_ARCH.X86_64)
            elif self.arch == Architecture.X86:
                self._triton.setArchitecture(TRITON_ARCH.X86)
            elif self.arch == Architecture.ARM64:
                self._triton.setArchitecture(TRITON_ARCH.AARCH64)

            self._triton.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
            logger.debug("Triton initialized for %s", self.arch.value)

        except Exception as e:
            logger.warning("Failed to initialize Triton: %s", e)
            self._triton = None

    def reset(self) -> None:
        """Reset emulation state."""
        self._instruction_count = 0
        self._memory_accesses.clear()

        if self._uc:
            # Re-initialize Unicorn
            self._init_unicorn()

        if self._triton:
            self._triton.reset()

    # ========== Unicorn Concrete Execution ==========

    def emulate_block(
        self,
        code: bytes,
        start_addr: int = CODE_BASE,
        initial_regs: dict[str, int] | None = None,
        initial_mem: dict[int, bytes] | None = None,
        max_instructions: int | None = None,
    ) -> EmulationState:
        """
        Emulate a block of code with Unicorn.

        Args:
            code: Machine code bytes to execute
            start_addr: Address where code is loaded
            initial_regs: Initial register values
            initial_mem: Initial memory contents
            max_instructions: Max instructions to execute

        Returns:
            EmulationState with final register/memory state
        """
        if not self.has_unicorn:
            return EmulationState(stopped=True, stop_reason="Unicorn not available")

        max_ins = max_instructions or self.MAX_INSTRUCTIONS
        self._instruction_count = 0
        self._memory_accesses.clear()

        try:
            # Write code
            self._uc.mem_write(start_addr, code)

            # Set initial registers
            if initial_regs:
                for reg_name, value in initial_regs.items():
                    reg_id = self._reg_name_to_id(reg_name)
                    if reg_id is not None:
                        self._uc.reg_write(reg_id, value)

            # Set initial memory
            if initial_mem:
                for addr, data in initial_mem.items():
                    self._map_if_needed(addr, len(data))
                    self._uc.mem_write(addr, data)

            # Add hooks
            def hook_code(uc, address, size, user_data):
                self._instruction_count += 1
                if self._instruction_count >= max_ins:
                    uc.emu_stop()

            def hook_mem_access(uc, access, address, size, value, user_data):
                is_write = access == UC_MEM_WRITE
                self._memory_accesses.append((address, size, is_write))

            hook_code_handle = self._uc.hook_add(UC_HOOK_CODE, hook_code)
            hook_mem_handle = self._uc.hook_add(
                UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access
            )

            # Run emulation
            end_addr = start_addr + len(code)
            self._uc.emu_start(start_addr, end_addr, timeout=self.TIMEOUT_MS * 1000)

            # Clean up hooks
            self._uc.hook_del(hook_code_handle)
            self._uc.hook_del(hook_mem_handle)

            # Capture final state
            return self._capture_state()

        except Exception as e:
            logger.debug("Emulation error: %s", e)
            return EmulationState(stopped=True, stop_reason=str(e))

    def trace_state_variable(
        self,
        code: bytes,
        state_var_offset: int,
        initial_state: int,
        start_addr: int = CODE_BASE,
    ) -> list[StateTransition]:
        """
        Trace state variable changes through code execution.

        Args:
            code: Machine code to execute
            state_var_offset: Stack offset of state variable (relative to initial RSP)
            initial_state: Initial state value
            start_addr: Code base address

        Returns:
            List of state transitions observed
        """
        if not self.has_unicorn:
            return []

        transitions = []
        current_state = initial_state

        # Set up state variable on stack
        if self.arch == Architecture.X86_64:
            sp = self.STACK_BASE + self.STACK_SIZE - 0x1000
            state_addr = sp + state_var_offset
        else:
            return []  # TODO: Support other architectures

        # Write initial state
        initial_mem = {
            state_addr: struct.pack(
                "<Q" if self.arch == Architecture.X86_64 else "<I", initial_state
            )
        }

        result = self.emulate_block(code, start_addr, initial_mem=initial_mem)

        # Check memory accesses for state variable writes
        for addr, size, is_write in self._memory_accesses:
            if is_write and addr == state_addr:
                # Read new state value
                try:
                    new_state_bytes = self._uc.mem_read(
                        state_addr, 8 if self.arch == Architecture.X86_64 else 4
                    )
                    new_state = struct.unpack(
                        "<Q" if self.arch == Architecture.X86_64 else "<I",
                        new_state_bytes,
                    )[0]

                    if new_state != current_state:
                        transitions.append(
                            StateTransition(
                                from_value=current_state,
                                to_value=new_state,
                                is_proven=True,  # Concretely observed
                            )
                        )
                        current_state = new_state
                except Exception:
                    pass

        return transitions

    def _capture_state(self) -> EmulationState:
        """Capture current emulation state."""
        state = EmulationState()

        if self.arch == Architecture.X86_64:
            reg_map = {
                "rax": UC_X86_REG_RAX,
                "rbx": UC_X86_REG_RBX,
                "rcx": UC_X86_REG_RCX,
                "rdx": UC_X86_REG_RDX,
                "rsi": UC_X86_REG_RSI,
                "rdi": UC_X86_REG_RDI,
                "rbp": UC_X86_REG_RBP,
                "rsp": UC_X86_REG_RSP,
                "r8": UC_X86_REG_R8,
                "r9": UC_X86_REG_R9,
                "r10": UC_X86_REG_R10,
                "r11": UC_X86_REG_R11,
                "r12": UC_X86_REG_R12,
                "r13": UC_X86_REG_R13,
                "r14": UC_X86_REG_R14,
                "r15": UC_X86_REG_R15,
                "rip": UC_X86_REG_RIP,
            }
            state.flags = self._uc.reg_read(UC_X86_REG_EFLAGS)
            state.pc = self._uc.reg_read(UC_X86_REG_RIP)
        elif self.arch == Architecture.X86:
            reg_map = {
                "eax": UC_X86_REG_EAX,
                "ebx": UC_X86_REG_EBX,
                "ecx": UC_X86_REG_ECX,
                "edx": UC_X86_REG_EDX,
                "esi": UC_X86_REG_ESI,
                "edi": UC_X86_REG_EDI,
                "ebp": UC_X86_REG_EBP,
                "esp": UC_X86_REG_ESP,
                "eip": UC_X86_REG_EIP,
            }
            state.flags = self._uc.reg_read(UC_X86_REG_EFLAGS)
            state.pc = self._uc.reg_read(UC_X86_REG_EIP)
        else:
            reg_map = {}

        for name, reg_id in reg_map.items():
            try:
                state.registers[name] = self._uc.reg_read(reg_id)
            except Exception:
                pass

        return state

    def _reg_name_to_id(self, name: str) -> int | None:
        """Convert register name to Unicorn register ID."""
        if not UNICORN_AVAILABLE:
            return None

        name = name.lower()

        if self.arch == Architecture.X86_64:
            reg_map = {
                "rax": UC_X86_REG_RAX,
                "rbx": UC_X86_REG_RBX,
                "rcx": UC_X86_REG_RCX,
                "rdx": UC_X86_REG_RDX,
                "rsi": UC_X86_REG_RSI,
                "rdi": UC_X86_REG_RDI,
                "rbp": UC_X86_REG_RBP,
                "rsp": UC_X86_REG_RSP,
                "r8": UC_X86_REG_R8,
                "r9": UC_X86_REG_R9,
                "r10": UC_X86_REG_R10,
                "r11": UC_X86_REG_R11,
                "r12": UC_X86_REG_R12,
                "r13": UC_X86_REG_R13,
                "r14": UC_X86_REG_R14,
                "r15": UC_X86_REG_R15,
                "rip": UC_X86_REG_RIP,
            }
        elif self.arch == Architecture.X86:
            reg_map = {
                "eax": UC_X86_REG_EAX,
                "ebx": UC_X86_REG_EBX,
                "ecx": UC_X86_REG_ECX,
                "edx": UC_X86_REG_EDX,
                "esi": UC_X86_REG_ESI,
                "edi": UC_X86_REG_EDI,
                "ebp": UC_X86_REG_EBP,
                "esp": UC_X86_REG_ESP,
                "eip": UC_X86_REG_EIP,
            }
        else:
            reg_map = {}

        return reg_map.get(name)

    def _map_if_needed(self, addr: int, size: int) -> None:
        """Map memory region if not already mapped."""
        if not self._uc:
            return

        # Align to page boundary
        page_size = 0x1000
        start = (addr // page_size) * page_size
        end = ((addr + size + page_size - 1) // page_size) * page_size

        try:
            # Check if already mapped by trying to read
            self._uc.mem_read(addr, 1)
        except Exception:
            # Not mapped, map it
            try:
                self._uc.mem_map(start, end - start)
            except Exception:
                pass  # Already mapped or overlap

    # ========== Triton Symbolic Execution ==========

    def prove_branch(
        self,
        condition_ast,
        constraints: list | None = None,
    ) -> tuple[bool | None, dict]:
        """
        Prove or refute a branch condition using symbolic execution.

        Args:
            condition_ast: Triton AST representing the condition
            constraints: Additional path constraints

        Returns:
            (True, model) if condition is always true
            (False, model) if condition is always false
            (None, {}) if undecidable
        """
        if not self.has_triton:
            return (None, {})

        try:
            # Add any additional constraints
            if constraints:
                for c in constraints:
                    self._triton.pushPathConstraint(c)

            # Check validity: condition is valid iff ¬condition is unsat
            neg_cond = self._triton.getAstContext().lnot(condition_ast)

            if not self._triton.isSat(neg_cond):
                # ¬condition is unsat → condition is always true
                return (True, {})

            # Check if condition is unsat
            if not self._triton.isSat(condition_ast):
                return (False, {})

            # Undecidable
            return (None, {})

        except Exception as e:
            logger.debug("Triton prove error: %s", e)
            return (None, {})

    def enumerate_values(
        self,
        expr_ast,
        max_values: int = 8,
    ) -> list[int] | None:
        """
        Enumerate possible values for a symbolic expression.

        Args:
            expr_ast: Triton AST expression
            max_values: Maximum number of values to enumerate

        Returns:
            List of possible values, or None if too many/undecidable
        """
        if not self.has_triton:
            return None

        try:
            values = []
            ast_ctx = self._triton.getAstContext()

            for _ in range(max_values):
                if self._triton.isSat(ast_ctx.equal(expr_ast, expr_ast)):
                    model = self._triton.getModel(ast_ctx.equal(expr_ast, expr_ast))
                    if not model:
                        break

                    # Get concrete value from model
                    value = expr_ast.evaluate()
                    if value is not None and value not in values:
                        values.append(value)
                        # Add constraint to exclude this value
                        self._triton.pushPathConstraint(
                            ast_ctx.lnot(
                                ast_ctx.equal(
                                    expr_ast,
                                    ast_ctx.bv(value, expr_ast.getBitvectorSize()),
                                )
                            )
                        )
                    else:
                        break
                else:
                    break

            return values if values else None

        except Exception as e:
            logger.debug("Triton enumerate error: %s", e)
            return None


# Convenience function for quick oracle creation
def create_oracle(arch: str = "auto") -> EmulationOracle:
    """
    Create an emulation oracle, auto-detecting architecture if needed.

    Args:
        arch: Architecture string ("x86", "x86_64", "arm64") or "auto"

    Returns:
        Configured EmulationOracle instance
    """
    if arch == "auto":
        # Default to x86_64 for now
        # TODO: Auto-detect from IDA database
        arch = "x86_64"

    return EmulationOracle.create(arch)
