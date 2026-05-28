from __future__ import annotations

from dataclasses import dataclass

from d810.recon.flow.bst_model import is_terminal_handler


@dataclass
class _Block:
    succs: tuple[int, ...]

    def nsucc(self) -> int:
        return len(self.succs)

    def succ(self, idx: int) -> int:
        return self.succs[idx]


class _Mba:
    def __init__(self, blocks: dict[int, _Block]) -> None:
        self._blocks = blocks
        self.qty = len(blocks)

    def get_mblock(self, serial: int) -> _Block | None:
        return self._blocks.get(int(serial))


def test_terminal_handler_accepts_all_no_successor_paths() -> None:
    mba = _Mba({1: _Block((2, 3)), 2: _Block(()), 3: _Block(())})

    assert is_terminal_handler(mba, 1, dispatcher_serial=9, bst_blocks=set())


def test_terminal_handler_rejects_path_to_dispatcher() -> None:
    mba = _Mba({1: _Block((2, 9)), 2: _Block(()), 9: _Block(())})

    assert not is_terminal_handler(mba, 1, dispatcher_serial=9, bst_blocks=set())


def test_terminal_handler_rejects_path_to_bst_block() -> None:
    mba = _Mba({1: _Block((2, 4)), 2: _Block(()), 4: _Block(())})

    assert not is_terminal_handler(mba, 1, dispatcher_serial=9, bst_blocks={4})
