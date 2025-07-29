import contextlib
import os

import idaapi

from d810.manager import D810State


def pseudocode_to_string(pseudo_code: idaapi.strvec_t) -> str:
    converted_obj: list[str] = [
        idaapi.tag_remove(line_obj.line) for line_obj in pseudo_code
    ]

    return os.linesep.join(converted_obj)


@contextlib.contextmanager
def d810_state():
    state = D810State()  # singleton
    if not (was_loaded := state.is_loaded()):
        state.load(gui=False)
    if not (was_started := state.manager.started):
        state.start_d810()
    yield state
    if not was_started:
        state.stop_d810()
    if not was_loaded:
        state.unload(gui=False)
