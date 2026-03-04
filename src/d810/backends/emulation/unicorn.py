"""Unicorn-based concrete emulation backend."""

from __future__ import annotations

import struct

from d810.backends.emulation.common import Architecture, EmulationState, StateTransition, logger

try:
    from unicorn import (
        UC_ARCH_ARM64,
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_WRITE,
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


class UnicornEmulator:
    """Concrete execution backend implemented with Unicorn."""

    CODE_BASE = 0x10000
    STACK_BASE = 0x80000
    STACK_SIZE = 0x10000
    HEAP_BASE = 0x100000
    HEAP_SIZE = 0x10000
    MAX_INSTRUCTIONS = 1000
    TIMEOUT_MS = 100

    def __init__(self, arch: Architecture = Architecture.X86_64):
        self.arch = arch
        self._uc: Uc | None = None
        self._instruction_count = 0
        self._memory_accesses: list[tuple[int, int, bool]] = []
        self._init_unicorn()

    @property
    def available(self) -> bool:
        return self._uc is not None

    def reset(self) -> None:
        self._instruction_count = 0
        self._memory_accesses.clear()
        if self._uc:
            self._init_unicorn()

    def emulate_block(
        self,
        code: bytes,
        start_addr: int = CODE_BASE,
        initial_regs: dict[str, int] | None = None,
        initial_mem: dict[int, bytes] | None = None,
        max_instructions: int | None = None,
    ) -> EmulationState:
        if not self.available:
            return EmulationState(stopped=True, stop_reason="Unicorn not available")

        max_ins = max_instructions or self.MAX_INSTRUCTIONS
        self._instruction_count = 0
        self._memory_accesses.clear()

        try:
            assert self._uc is not None
            self._uc.mem_write(start_addr, code)

            if initial_regs:
                for reg_name, value in initial_regs.items():
                    reg_id = self._reg_name_to_id(reg_name)
                    if reg_id is not None:
                        self._uc.reg_write(reg_id, value)

            if initial_mem:
                for addr, data in initial_mem.items():
                    self._map_if_needed(addr, len(data))
                    self._uc.mem_write(addr, data)

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

            end_addr = start_addr + len(code)
            self._uc.emu_start(start_addr, end_addr, timeout=self.TIMEOUT_MS * 1000)

            self._uc.hook_del(hook_code_handle)
            self._uc.hook_del(hook_mem_handle)

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
        if not self.available:
            return []

        transitions: list[StateTransition] = []
        current_state = initial_state

        if self.arch == Architecture.X86_64:
            sp = self.STACK_BASE + self.STACK_SIZE - 0x1000
            state_addr = sp + state_var_offset
        else:
            return []

        initial_mem = {
            state_addr: struct.pack(
                "<Q" if self.arch == Architecture.X86_64 else "<I", initial_state
            )
        }

        self.emulate_block(code, start_addr, initial_mem=initial_mem)

        for addr, size, is_write in self._memory_accesses:
            if is_write and addr == state_addr:
                try:
                    assert self._uc is not None
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
                                is_proven=True,
                            )
                        )
                        current_state = new_state
                except Exception:
                    pass

        return transitions

    def _init_unicorn(self) -> None:
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

            self._uc.mem_map(self.CODE_BASE, 0x10000)
            self._uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
            self._uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE)

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

    def _capture_state(self) -> EmulationState:
        state = EmulationState()
        assert self._uc is not None

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
        if not self._uc:
            return

        page_size = 0x1000
        start = (addr // page_size) * page_size
        end = ((addr + size + page_size - 1) // page_size) * page_size

        try:
            self._uc.mem_read(addr, 1)
        except Exception:
            try:
                self._uc.mem_map(start, end - start)
            except Exception:
                pass

