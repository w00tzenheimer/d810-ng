"""Native-proxy identity must not truncate provider block fingerprints."""

from types import SimpleNamespace

from d810.hexrays.hooks import optinsn_adapter


class _InstructionProxy:
    """Model SWIG's fresh wrapper on each linked-instruction access."""

    def __init__(self, pointers, index=0):
        self.pointers = pointers
        self.index = index
        self.this = pointers[index]
        self.ea = 0x401000  # Distinct native instructions may share an EA.
        self.opcode = 12

    def _print(self):
        return f"instruction-{self.index}"

    @property
    def next(self):
        index = self.index + 1
        if index == len(self.pointers):
            return None
        return type(self)(self.pointers, index)


def test_recycled_python_identity_does_not_truncate_native_chain(monkeypatch):
    # Deterministically model a recycled wrapper ID without allocator dependence.
    monkeypatch.setattr(optinsn_adapter, "id", lambda _proxy: 7, raising=False)
    block = SimpleNamespace(head=_InstructionProxy((101, 102, 103)))
    assert optinsn_adapter._external_provider_block_body(block) == (
        (0x401000, 12, "instruction-0"),
        (0x401000, 12, "instruction-1"),
        (0x401000, 12, "instruction-2"),
    )


def test_fresh_proxies_revisiting_native_instruction_are_a_cycle(monkeypatch):
    # Give each wrapper a distinct synthetic Python identity: the native node
    # still repeats. A real-cycle guard must not rely on wrapper reuse.
    monkeypatch.setattr(
        optinsn_adapter, "id", lambda proxy: proxy.index, raising=False
    )
    block = SimpleNamespace(head=_InstructionProxy((101, 102, 101)))
    assert optinsn_adapter._external_provider_block_body(block) is None


def test_same_ea_distinct_native_instructions_are_not_a_cycle():
    block = SimpleNamespace(head=_InstructionProxy((101, 102)))
    assert optinsn_adapter._external_provider_block_body(block) == (
        (0x401000, 12, "instruction-0"),
        (0x401000, 12, "instruction-1"),
    )


def test_real_python_object_cycle_is_rejected():
    instruction = SimpleNamespace(ea=0x401000, opcode=12, _print=lambda: "loop")
    instruction.next = instruction
    assert optinsn_adapter._external_provider_block_body(
        SimpleNamespace(head=instruction)
    ) is None
