"""Reaching-defs-sound static-initializer folding of data-dependent globals.

Validates :func:`compute_initializer_stable_global_reads`: a writable global
read folds to its ``.data`` initializer ONLY when no store to that global
reaches the read (per read site), strictly narrower than blanket
``fold_writable_constants``.
"""
from __future__ import annotations

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.analyses.value_flow.global_init_fold import (
    compute_initializer_stable_global_reads,
)

# Opcode ids are diagnostic here; the analysis keys on operand gaddr, not opcode.
_OP_MOV = 0x04
_OP_OR = 0x13
_OP_GOTO = 0x37

_GADDR = 0x180021320  # approov_qword analog
_OTHER = 0x180021318  # approov_global_state analog


def _gread(gaddr: int = _GADDR, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=7, size=size, gaddr=gaddr)


def _gwrite(gaddr: int = _GADDR, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=7, size=size, gaddr=gaddr)


def _const(value: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=4, size=size, value=value)


def _block(serial, succs, preds, insns) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if len(succs) <= 1 else 2,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x100,
        insn_snapshots=tuple(insns),
    )


def _fetch_zero(addr, size):
    # The loader-supplied initializer: both globals are zero-initialised .data.
    return 0


def test_entry_read_before_any_store_folds():
    """A read in the entry block, before any store, folds to the initializer."""
    # entry: rax = (qword | 0xF6A20) ; qword = rax     (Approov 0xF6A1F handler)
    read_ea = 0x2000
    store_ea = 0x2008
    entry = _block(
        0,
        succs=(1,),
        preds=(),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=read_ea,
                operands=(),
                l=_gread(),
                r=_const(0xF6A20),
                d=MopSnapshot(t=1, size=8, reg=0),  # rax
            ),
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=store_ea,
                operands=(),
                l=MopSnapshot(t=1, size=8, reg=0),
                d=_gwrite(),  # store to qword
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2010, operands=()),
        ],
    )
    tail = _block(1, succs=(), preds=(0,), insns=[])
    fg = FlowGraph(blocks={0: entry, 1: tail}, entry_serial=0, func_ea=0x1000)

    foldable = compute_initializer_stable_global_reads(fg, _fetch_zero)
    assert read_ea in foldable, "entry read before its store must fold"
    assert foldable[read_ea][_GADDR] == 0


def test_read_after_reaching_store_is_rejected():
    """A read whose value can come from a store on some path does NOT fold."""
    # block0 stores qword=5 then -> block1; block1 reads qword.  The store
    # reaches the read, so folding to the initializer would be UNSOUND.
    store_ea = 0x2000
    read_ea = 0x2100
    b0 = _block(
        0,
        succs=(1,),
        preds=(),
        insns=[
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=store_ea,
                operands=(),
                l=_const(5),
                d=_gwrite(),
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2008, operands=()),
        ],
    )
    b1 = _block(
        1,
        succs=(),
        preds=(0,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=read_ea,
                operands=(),
                l=_gread(),
                r=_const(0x40),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
        ],
    )
    fg = FlowGraph(blocks={0: b0, 1: b1}, entry_serial=0, func_ea=0x1000)

    foldable = compute_initializer_stable_global_reads(fg, _fetch_zero)
    assert read_ea not in foldable, "read with a reaching store must NOT fold"


def test_intra_block_store_before_read_rejects():
    """A store earlier in the SAME block as the read rejects the fold."""
    store_ea = 0x2000
    read_ea = 0x2008
    b0 = _block(
        0,
        succs=(),
        preds=(),
        insns=[
            InsnSnapshot(
                opcode=_OP_MOV, ea=store_ea, operands=(), l=_const(7), d=_gwrite()
            ),
            InsnSnapshot(
                opcode=_OP_OR,
                ea=read_ea,
                operands=(),
                l=_gread(),
                r=_const(0x40),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
        ],
    )
    fg = FlowGraph(blocks={0: b0}, entry_serial=0, func_ea=0x1000)

    foldable = compute_initializer_stable_global_reads(fg, _fetch_zero)
    assert read_ea not in foldable


def test_per_site_granularity_same_global_both_outcomes():
    """The SAME global folds at the entry read but not at a later post-store read."""
    # entry block: read qword (foldable), then store qword, goto block1.
    # block1: read qword again (NOT foldable -- entry's store reaches it).
    entry_read = 0x2000
    entry_store = 0x2008
    later_read = 0x2100
    b0 = _block(
        0,
        succs=(1,),
        preds=(),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=entry_read,
                operands=(),
                l=_gread(),
                r=_const(0xF6A20),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=entry_store,
                operands=(),
                l=MopSnapshot(t=1, size=8, reg=0),
                d=_gwrite(),
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2010, operands=()),
        ],
    )
    b1 = _block(
        1,
        succs=(),
        preds=(0,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=later_read,
                operands=(),
                l=_gread(),
                r=_const(0x40),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
        ],
    )
    fg = FlowGraph(blocks={0: b0, 1: b1}, entry_serial=0, func_ea=0x1000)

    foldable = compute_initializer_stable_global_reads(fg, _fetch_zero)
    assert entry_read in foldable and foldable[entry_read][_GADDR] == 0
    assert later_read not in foldable, "later read after reaching store must NOT fold"


def test_nested_subexpression_read_detected():
    """A global read inside a nested mop_d subexpression is detected and folds."""
    read_ea = 0x2000
    nested = MopSnapshot(
        t=6,  # mop_d
        size=8,
        sub_l=_gread(),
        sub_r=_const(0xF6A20),
    )
    b0 = _block(
        0,
        succs=(),
        preds=(),
        insns=[
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=read_ea,
                operands=(),
                l=nested,
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
        ],
    )
    fg = FlowGraph(blocks={0: b0}, entry_serial=0, func_ea=0x1000)
    foldable = compute_initializer_stable_global_reads(fg, _fetch_zero)
    assert read_ea in foldable and foldable[read_ea][_GADDR] == 0


def test_loop_back_edge_store_reaches_header_read():
    """A store on a loop back-edge reaches the header read on the second iteration."""
    # header(0) reads qword; body(1) stores qword and loops back to header.
    # The store reaches the header read via the back-edge -> NOT foldable.
    header_read = 0x2000
    body_store = 0x2100
    b0 = _block(
        0,
        succs=(1,),
        preds=(1,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=header_read,
                operands=(),
                l=_gread(),
                r=_const(1),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
        ],
    )
    b1 = _block(
        1,
        succs=(0,),
        preds=(0,),
        insns=[
            InsnSnapshot(
                opcode=_OP_MOV, ea=body_store, operands=(), l=_const(9), d=_gwrite()
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2108, operands=()),
        ],
    )
    fg = FlowGraph(blocks={0: b0, 1: b1}, entry_serial=0, func_ea=0x1000)
    foldable = compute_initializer_stable_global_reads(fg, _fetch_zero)
    assert header_read not in foldable, "back-edge store reaches header read"


def test_dispatcher_barrier_folds_initial_handler_read():
    """Approov shape: the initial handler reads the global before any store.

    entry(0) -> handler7 (reads qword, then stores qword) -> dispatcher(2) -> ...
    The handler's store reaches its own read ONLY via the infeasible dispatcher
    self-loop (7->2->...->7).  Cutting edges into the dispatcher barrier exposes
    the straight-line entry path (0->7) where no store precedes the read, so the
    read folds soundly.  Without the barrier it would be (over-conservatively)
    rejected.
    """
    read_ea = 0x2000
    store_ea = 0x2008
    # 0: entry -> 7
    b0 = _block(0, succs=(7,), preds=(), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x1f00, operands=())])
    # 7: initial handler -- read qword, then store qword, goto dispatcher(2)
    b7 = _block(
        7,
        succs=(2,),
        preds=(0, 3),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=read_ea,
                operands=(),
                l=_gread(),
                r=_const(0xF6A20),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=store_ea,
                operands=(),
                l=MopSnapshot(t=1, size=8, reg=0),
                d=_gwrite(),
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2010, operands=()),
        ],
    )
    # 2: dispatcher head -> 3 ; 3 -> 7 (routes back to handler 7)
    b2 = _block(2, succs=(3,), preds=(7,), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x2100, operands=())])
    b3 = _block(3, succs=(7,), preds=(2,), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x2108, operands=())])
    fg = FlowGraph(blocks={0: b0, 7: b7, 2: b2, 3: b3}, entry_serial=0, func_ea=0x1000)

    # Without the barrier: rejected (the self-loop store reaches).
    assert read_ea not in compute_initializer_stable_global_reads(fg, _fetch_zero)
    # With the dispatcher(2) as barrier: folds (straight-line entry path is store-free).
    folded = compute_initializer_stable_global_reads(fg, _fetch_zero, barrier_serials={2})
    assert read_ea in folded and folded[read_ea][_GADDR] == 0


def test_barrier_unreachable_block_not_folded():
    """A handler reached ONLY via the dispatcher is unreachable once cut -> no fold.

    Soundness guard: cutting dispatcher-in edges disconnects handlers reached
    only by routing.  Their store-freeness is unproven, so their global reads
    must NOT fold (a store from another handler could reach them at runtime).
    """
    read_ea = 0x2200
    # entry(0) -> dispatcher(2) -> handler9 (reads qword).  No direct entry->9.
    b0 = _block(0, succs=(2,), preds=(), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x1f00, operands=())])
    b2 = _block(2, succs=(9,), preds=(9,), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x2100, operands=())])
    b9 = _block(
        9,
        succs=(2,),
        preds=(2,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=read_ea,
                operands=(),
                l=_gread(),
                r=_const(0x40),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2208, operands=()),
        ],
    )
    fg = FlowGraph(blocks={0: b0, 2: b2, 9: b9}, entry_serial=0, func_ea=0x1000)
    folded = compute_initializer_stable_global_reads(fg, _fetch_zero, barrier_serials={2})
    assert read_ea not in folded, "dispatcher-only handler is unproven -> no fold"


def test_entry_override_anchors_at_initial_handler():
    """Approov real shape: the prologue enters the DISPATCHER, not the handler.

    entry(0)->dispatcher(2)->handler7 (reads then stores qword)->dispatcher(2).
    The initial handler (7) is reached only THROUGH the dispatcher, so anchoring
    at the function entry + cutting the dispatcher leaves handler 7 unreachable
    (no fold).  Anchoring reaching-defs at the initial handler (7) -- the
    dispatcher's target for the entry state -- with the dispatcher(2) barrier
    yields the real execution prefix: handler 7 runs first, store-free read folds.
    """
    read_ea = 0x2000
    store_ea = 0x2008
    b0 = _block(0, succs=(2,), preds=(), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x1f00, operands=())])
    b2 = _block(2, succs=(7,), preds=(0, 7), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x2100, operands=())])
    b7 = _block(
        7,
        succs=(2,),
        preds=(2,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR,
                ea=read_ea,
                operands=(),
                l=_gread(),
                r=_const(0xF6A20),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=store_ea,
                operands=(),
                l=MopSnapshot(t=1, size=8, reg=0),
                d=_gwrite(),
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2010, operands=()),
        ],
    )
    fg = FlowGraph(blocks={0: b0, 2: b2, 7: b7}, entry_serial=0, func_ea=0x1000)

    # Barrier alone (anchored at function entry): handler 7 unreachable -> no fold.
    assert read_ea not in compute_initializer_stable_global_reads(
        fg, _fetch_zero, barrier_serials={2}
    )
    # Anchored at the initial handler 7 + dispatcher barrier: folds.
    folded = compute_initializer_stable_global_reads(
        fg, _fetch_zero, barrier_serials={2}, entry_override=7
    )
    assert read_ea in folded and folded[read_ea][_GADDR] == 0


def test_entry_override_other_handler_read_not_folded():
    """A non-initial handler's global read is unreachable from the initial -> no fold.

    Soundness: handler6 reads qword for its return value; it is reached only via
    the dispatcher.  Anchored at the initial handler(7) with the dispatcher cut,
    handler6 is unreachable -> not folded (at runtime a prior handler's store
    reaches it, so folding to the initializer would be unsound).
    """
    h7_read = 0x2000
    h7_store = 0x2008
    h6_read = 0x2100
    b0 = _block(0, succs=(2,), preds=(), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x1f00, operands=())])
    b2 = _block(2, succs=(7, 6), preds=(0, 7, 6), insns=[InsnSnapshot(opcode=_OP_GOTO, ea=0x2050, operands=())])
    b7 = _block(
        7,
        succs=(2,),
        preds=(2,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR, ea=h7_read, operands=(), l=_gread(), r=_const(0xF6A20),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
            InsnSnapshot(
                opcode=_OP_MOV, ea=h7_store, operands=(),
                l=MopSnapshot(t=1, size=8, reg=0), d=_gwrite(),
            ),
            InsnSnapshot(opcode=_OP_GOTO, ea=0x2010, operands=()),
        ],
    )
    b6 = _block(
        6,
        succs=(),
        preds=(2,),
        insns=[
            InsnSnapshot(
                opcode=_OP_OR, ea=h6_read, operands=(), l=_gread(), r=_const(0x40),
                d=MopSnapshot(t=1, size=8, reg=0),
            ),
        ],
    )
    fg = FlowGraph(blocks={0: b0, 2: b2, 7: b7, 6: b6}, entry_serial=0, func_ea=0x1000)
    folded = compute_initializer_stable_global_reads(
        fg, _fetch_zero, barrier_serials={2}, entry_override=7
    )
    assert h7_read in folded, "initial handler read folds"
    assert h6_read not in folded, "non-initial handler read must NOT fold"


def test_no_globals_returns_empty():
    b0 = _block(
        0,
        succs=(),
        preds=(),
        insns=[
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=0x2000,
                operands=(),
                l=_const(1),
                d=MopSnapshot(t=1, size=4, reg=0),
            )
        ],
    )
    fg = FlowGraph(blocks={0: b0}, entry_serial=0, func_ea=0x1000)
    assert compute_initializer_stable_global_reads(fg, _fetch_zero) == {}
