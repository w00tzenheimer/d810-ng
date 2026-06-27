"""DEFFAI set-valued block transfer + per-arm condvar refinement (the ``assume``).

The DEFFAI transfer lifts the proven *single-block exact-constant* fold
(:func:`d810.analyses.control_flow.state_machine_analysis._transfer_snapshot_constant_block`,
which carries ``dict[off -> int]`` -- one value per cell) to a **set** transfer
that carries ``dict[off -> StateValue]`` (a powerset per cell) and **forks** at a
2-way branch into per-arm stores:

* **Singleton fast-path** -- when every cell the block reads holds a singleton
  set, project to the scalar maps the proven fold expects, run it once, lift the
  result back to singletons.  This is byte-parity with the scalar transfer (the
  Step-3 parity test).
* **Multi-value product** -- when a cell is multi-valued, run the scalar fold
  once per element of the (bounded) product over the read cells and ``join`` the
  per-element results into the out set.  This realizes the set-domain transfer
  ``f#(M#) = lub_{sigma in gamma(M#)} alpha(f(sigma))`` over a *bounded*
  concretization; past the cap the cell degrades to ``top`` (sound over-approx).
* **2-way fork (DEFFAI Fig.6 ``state |-> {a,b}``)** -- the taken / not-taken arms
  are returned separately, EACH refined by its branch predicate via
  :meth:`StateValue.meet_const` (the equal arm) / :meth:`StateValue.exclude` (the
  not-equal arm).  Arm ``assume`` only *removes* infeasible values (a glb
  refinement -- it can shrink to ``bottom`` but never invent a value), so a dead
  dispatcher edge surfaces as ``bottom``, never a wrong edge.
* **``switch_cases`` fan-out (jtbl)** -- a TABLE_JUMP tail forks one arm per case
  row, refining the state cell to that case's value set.

The scalar fold is supplied through an **injectable** ``block_evaluator`` seam so
this module stays portable (its default resolves the registry-backed
``_transfer_snapshot_constant_block`` *lazily at call time* -- the import of that
function is portable, only its evaluation touches the Hex-Rays seam).  Unit tests
inject a pure-Python evaluator; production keeps the proven fold.

Portable-core: no IDA imports.

d81-qlal -- canonical Instruction port.  This module's cell-discovery readers
used to reach into the backend-shaped ``InsnSnapshot`` operand slots
(``insn.l`` / ``insn.r`` / ``insn.d``) and feed the raw operand to
:func:`operand_cell`.  They now read the per-instruction operand evidence off the
canonical :func:`~d810.ir.insn_projection.project_instruction` projection:

* the cells a block *reads* come from ``Instruction.inputs`` (the projection's
  ``_VarnodeProjector.input_nodes`` already exposes the flattened stack-ref
  varnodes of a nested ``(state & mask)`` source, so the same tracked cell the
  ``stack_refs[0]`` fallback surfaced is recovered -- via a real ``Varnode``);
* the cell a block *writes* comes from ``Instruction.result``;
* the conditional jump target (was ``tail.d.block_ref``) comes from
  ``Instruction.control.target``;
* the ``switch_cases`` fan-out (was ``tail.l`` / ``tail.d`` ``switch_cases``)
  comes from ``Instruction.control.switch_cases``;
* the compare's ``(const, condvar_cell)`` split (was ``tail.l`` / ``tail.r``)
  comes from the slot-aligned :func:`~d810.ir.insn_projection.operand_storages`
  views: a ``Space.CONST`` view is the literal, the other names the cell.

:func:`operand_cell` / :func:`mop_cell` remain the public lift-boundary cell
adapters (consumed by the deffai facade, ``ccm`` and the unit tests); they read
no operand slot and so are not part of the migrated-module guard surface.
"""
from __future__ import annotations

from itertools import product

from d810.core.typing import Callable, Mapping, Optional

from d810.ir.flowgraph import BlockSnapshot, InsnKind, InsnSnapshot
from d810.ir.insn_projection import (
    operand_stack_offsets,
    operand_storages,
    project_instruction,
)
from d810.ir.locations import WeakStackSlot
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot
from d810.ir.semantics import PredicateKind
from d810.analyses.control_flow.instruction_semantics import branch_predicate
from d810.analyses.control_flow.state_machine_analysis import (
    _transfer_snapshot_constant_block,
)
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow.concolic.refs import LocationRef

from d810.analyses.control_flow.deffai.powerset_store import PowersetStore

__all__ = [
    "ArmTransfer",
    "mop_cell",
    "operand_cell",
    "scalar_block_evaluator",
    "tail_condvar_cells",
    "transfer_block_set",
    "written_cell",
]

_U32_MASK = 0xFFFFFFFF

#: A scalar block evaluator: ``(block, in_stk, in_reg, state_var_stkoff) ->
#: (out_stk, out_reg)``.  Matches the signature of
#: ``_transfer_snapshot_constant_block`` (its keyword args default off).
BlockEvaluator = Callable[
    [BlockSnapshot, dict, dict, int], "tuple[dict[int, int], dict[int, int]]"
]


def mop_cell(vn: Varnode | None) -> LocationRef | None:
    """Map a canonical :class:`~d810.ir.varnode.Varnode` to the storage cell it
    names, or ``None``.

    A ``STACK`` varnode -> ``LocationRef.stack(off, width)``; a ``REGISTER``
    varnode -> ``LocationRef.reg(reg, width)``.  Width defaults to 8 (u64) when
    the varnode carries no size, matching the u64 mask state constants already
    use.  Returns ``None`` for a constant / unrecognized varnode (it names no
    tracked cell).
    """
    if vn is None:
        return None
    width = int(vn.size or 0) or 8
    if vn.space is Space.STACK:
        return LocationRef.stack(int(vn.offset), width)
    if vn.space is Space.REGISTER:
        return LocationRef.reg(int(vn.offset), width)
    return None


def operand_cell(mop: MopSnapshot | None) -> LocationRef | None:
    """Lift-boundary adapter: project a lifted operand snapshot to the storage
    cell it names, via the canonical ``Varnode`` surface.

    Stack/register operands convert directly through
    :func:`varnode_from_mop_snapshot`.  A nested expression operand that names
    no top-level varnode but carries flattened ``stack_refs`` (e.g.
    ``(state & mask)``) still resolves to its first referenced stack slot, so
    the read/write cell discovery keeps the same superset behavior it had over
    raw operand fields.

    This is the public cell adapter consumed by the deffai facade / ``ccm`` /
    the unit tests; it reads no ``l`` / ``r`` / ``d`` operand slot.  The
    ``stack_refs`` / ``size`` reads are portable :class:`MopSnapshot` fields
    (strong-typed), not backend operand slots, so they are outside the
    migrated-module operand-slot guard.
    """
    if mop is None:
        return None
    cell = mop_cell(varnode_from_mop_snapshot(mop))
    if cell is not None:
        return cell
    stack_refs = mop.stack_refs
    if stack_refs:
        size = int(mop.size or 0)
        return mop_cell(Varnode(Space.STACK, int(stack_refs[0]), size))
    return None


def _insn_read_cells(insn: InsnSnapshot) -> set[LocationRef]:
    """The tracked cells the instruction *reads* (the ``l`` / ``r`` source slots).

    Canonical replacement for ``operand_cell(insn.l) | operand_cell(insn.r)``: the
    two source operand storage views (:func:`~d810.ir.insn_projection.operand_storages`)
    map through :func:`_slot_cell`, which reproduces the direct-cell read and the
    nested ``(state & mask)`` stack-ref fallback at the source's width.  Only the
    source slots are read -- the dest slot (a store's target) is a *write*, never
    a read -- so the cell set is byte-identical to the legacy per-slot read for
    every instruction family (incl. ``m_stx`` STORE, whose dest is on ``d``).
    """
    left, right, _dest = operand_storages(insn)
    left_off, right_off, _dest_off = operand_stack_offsets(insn)
    cells: set[LocationRef] = set()
    for view, stack_offset in ((left, left_off), (right, right_off)):
        cell = _slot_cell(view, stack_offset)
        if cell is not None:
            cells.add(cell)
    return cells


def _insn_written_cell(insn: InsnSnapshot) -> LocationRef | None:
    """The tracked cell the instruction *writes* (the ``d`` dest slot).

    Canonical replacement for ``operand_cell(insn.d)``: the dest operand storage
    view (:func:`~d810.ir.insn_projection.result_storage`, i.e. the ``d`` slot
    view) maps through :func:`_slot_cell`.  This reads the dest slot directly --
    not ``Instruction.result`` -- so an ``m_stx`` STORE, whose written cell lives
    on ``d`` and is absent from the projection's ``result``, is still surfaced as
    the strong-update target (made ``top`` when unresolved), matching the legacy
    ``operand_cell(insn.d)`` read.
    """
    _left, _right, dest = operand_storages(insn)
    _left_off, _right_off, dest_off = operand_stack_offsets(insn)
    return _slot_cell(dest, dest_off)


def _slot_cell(
    view: Varnode | WeakStackSlot | None, stack_offset: int | None
) -> LocationRef | None:
    """The tracked cell an operand slot names, reproducing :func:`operand_cell`.

    Direct register / stack / lvar views map through :func:`mop_cell`; a nested
    expression operand (``Varnode(UNKNOWN)`` -- e.g. ``(state & mask)``) names no
    direct varnode cell, so the slot's lifted single stack reference
    (:func:`~d810.ir.insn_projection.operand_stack_offsets`) supplies the cell at
    the view's width, exactly as the legacy ``stack_refs[0]`` fallback did.
    """
    cell = mop_cell(view) if isinstance(view, Varnode) else None
    if cell is not None:
        return cell
    if stack_offset is not None:
        width = int(view.size or 0) if isinstance(view, Varnode) else 0
        return mop_cell(Varnode(Space.STACK, int(stack_offset), width))
    return None


def _const_of(view: Varnode | WeakStackSlot | None) -> int | None:
    """The literal value of a ``Space.CONST`` operand storage view, else ``None``."""
    if isinstance(view, Varnode) and view.space is Space.CONST:
        return int(view.offset)
    return None


def tail_condvar_cells(tail: InsnSnapshot) -> set[LocationRef]:
    """The tracked cells the tail *compares* (every non-constant source operand).

    Canonical replacement for ``operand_cell(tail.l) | operand_cell(tail.r)``
    filtered to non-``NUMBER`` operands: the two source operand storage views
    (:func:`~d810.ir.insn_projection.operand_storages`) map through
    :func:`_slot_cell`, skipping a ``Space.CONST`` view (the literal names no
    cell -- exactly the legacy ``kind is OperandKind.NUMBER`` skip).  Used by the
    preprocess condvar slice; the read/write cell helpers above use the same
    slot-aligned surface.
    """
    left, right, _dest = operand_storages(tail)
    left_off, right_off, _dest_off = operand_stack_offsets(tail)
    cells: set[LocationRef] = set()
    for view, stack_offset in ((left, left_off), (right, right_off)):
        if _const_of(view) is not None:
            continue
        cell = _slot_cell(view, stack_offset)
        if cell is not None:
            cells.add(cell)
    return cells


def written_cell(insn: InsnSnapshot) -> LocationRef | None:
    """The tracked cell ``insn`` writes (the ``d`` dest slot), or ``None``.

    Public alias of :func:`_insn_written_cell` so the preprocess slice reads the
    canonical written cell off the same slot-aligned surface the transfer uses,
    without importing a private helper.
    """
    return _insn_written_cell(insn)


def scalar_block_evaluator(state_var_stkoff: int) -> BlockEvaluator:
    """The default scalar fold, bound to ``state_var_stkoff`` (registry seam).

    Resolves :func:`_transfer_snapshot_constant_block` from
    ``state_machine_analysis`` at call time.  That fold delegates to the
    ``ConditionChainWalkerProvider`` seam (``forward_eval_insn``), so production reuses the
    proven evaluator; unit tests inject their own ``BlockEvaluator`` instead.

    The import is at module top (portable); only the *call* touches the seam.
    """

    def _evaluate(
        block: BlockSnapshot,
        in_stk: dict[int, int],
        in_reg: dict[int, int],
        _state_off: int,
    ) -> tuple[dict[int, int], dict[int, int]]:
        return _transfer_snapshot_constant_block(
            block, in_stk, in_reg, state_var_stkoff
        )

    return _evaluate


def _arm_targets(
    block: BlockSnapshot,
) -> tuple[Optional[int], Optional[int]]:
    """The (taken, fallthrough) successor serials of a 2-way branch tail.

    ``taken`` is the conditional branch's ``Instruction.control.target`` (the
    projection populates it from the tail's block operand ``block_ref``); the
    fallthrough is the block's other successor (mirrors
    ``dispatcher_discovery_extractors.extract_state_arm_comparisons``).  Returns
    ``(None, None)`` when the shape is not a clean 2-way branch.
    """
    tail = block.tail
    if tail is None or not tail.is_conditional_jump:
        return None, None
    control = project_instruction(tail).control
    taken = control.target if control is not None else None
    if taken is None:
        return None, None
    fallthrough = next((s for s in block.succs if s != taken), None)
    return int(taken), (None if fallthrough is None else int(fallthrough))


def _compare_const_and_cell(
    tail: InsnSnapshot,
) -> tuple[Optional[int], Optional[LocationRef]]:
    """Split a compare tail into ``(const, condvar_cell)``.

    One compared operand is a literal, the other names the condition variable's
    cell.  Read off the slot-aligned canonical
    :func:`~d810.ir.insn_projection.operand_storages` views (was ``tail.l`` /
    ``tail.r``): a ``Space.CONST`` view is the literal; the other view's named
    cell is the condvar.  Returns ``(None, None)`` when neither side is a plain
    constant.
    """
    left, right, _dest = operand_storages(tail)
    left_off, right_off, _dest_off = operand_stack_offsets(tail)
    for (const_view, _c_off), (cell_view, cell_off) in (
        ((left, left_off), (right, right_off)),
        ((right, right_off), (left, left_off)),
    ):
        const = _const_of(const_view)
        if const is not None:
            return const & _U32_MASK, _slot_cell(cell_view, cell_off)
    return None, None


def _read_cells(block: BlockSnapshot) -> frozenset[LocationRef]:
    """The cells the block *reads* (source operands ``l`` / ``r`` of each insn).

    Used to bound the multi-value product to only the cells whose value-set the
    fold actually consumes.  Conservative: any operand that maps to a cell is
    counted (a superset is sound -- it only widens the product, never drops a
    feasible combination).
    """
    cells: set[LocationRef] = set()
    for insn in block.insn_snapshots:
        cells |= _insn_read_cells(insn)
    return frozenset(cells)


def _written_cells(block: BlockSnapshot) -> frozenset[LocationRef]:
    """The cells the block *writes* (the dest operand ``d`` of each insn).

    Used to detect a strong-update whose source the scalar fold could not resolve
    (an MBA / register / computed write to a tracked cell): such a write makes the
    cell's value *unknown*, so it must become ``top`` (DEFFAI's data-obfuscated
    next-state), NOT be killed (which would read as ``bottom`` / unreachable) and
    NOT pass through the stale incoming value.
    """
    cells: set[LocationRef] = set()
    for insn in block.insn_snapshots:
        cell = _insn_written_cell(insn)
        if cell is not None:
            cells.add(cell)
    return frozenset(cells)


def _store_to_scalar_maps(
    assignment: Mapping[LocationRef, int],
) -> tuple[dict[int, int], dict[int, int]]:
    """Project a per-cell concrete ``assignment`` to (stk_map, reg_map)."""
    stk: dict[int, int] = {}
    reg: dict[int, int] = {}
    for cell, value in assignment.items():
        if cell.kind.name == "STACK":
            stk[cell.key] = int(value) & 0xFFFFFFFFFFFFFFFF
        else:
            reg[cell.key] = int(value) & 0xFFFFFFFFFFFFFFFF
    return stk, reg


def _lift_scalar_maps(
    out_stk: Mapping[int, int],
    out_reg: Mapping[int, int],
    tracked: frozenset[LocationRef],
) -> dict[LocationRef, StateValue]:
    """Lift the scalar (stk_map, reg_map) back to per-cell singleton sets.

    Every cell present in the out maps -- both stack offsets and register ids --
    is surfaced as a singleton set (a strong-update the block performed).  A
    tracked cell carries its own (possibly narrow) width; an untracked written
    cell is emitted at u64 width (the canonical width used across the DEFFAI core,
    where :func:`mop_cell` defaults to 8).  A cell absent from the out maps stays
    absent (``bottom``).
    """
    out: dict[LocationRef, StateValue] = {}
    # Preserve tracked-cell widths for cells that survive in the out maps.
    tracked_off = {c.key: c for c in tracked if c.kind.name == "STACK"}
    tracked_reg = {c.key: c for c in tracked if c.kind.name == "REGISTER"}
    for off, raw in out_stk.items():
        ref = tracked_off.get(int(off), LocationRef.stack(int(off), 8))
        out[ref] = StateValue.of(int(raw))
    for rid, raw in out_reg.items():
        ref = tracked_reg.get(int(rid), LocationRef.reg(int(rid), 8))
        out[ref] = StateValue.of(int(raw))
    return out


def _fold_block_set(
    block: BlockSnapshot,
    in_store: PowersetStore,
    *,
    block_evaluator: BlockEvaluator,
    state_var_stkoff: int,
    state_cell: LocationRef,
    max_product: int,
) -> PowersetStore:
    """Bounded set-valued fold of one block -> out-store (no fork).

    The shared core for both the no-branch successor and each 2-way arm:

    * gather the cells the block reads (plus the in-store cells);
    * if every read cell is a singleton, run the scalar fold once (the
      singleton fast-path == ``_transfer_snapshot_constant_block`` parity);
    * if a read cell is multi-valued, run the fold once per element of the
      product over the read cells and ``join`` the results (the set transfer
      ``lub alpha(f(sigma))``);
    * if any read cell is ``top``, or the product exceeds ``max_product``,
      degrade the *written* cells to ``top`` (sound over-approx) rather than
      enumerate.

    Cells the block does not touch pass through from ``in_store`` unchanged.
    """
    tracked = frozenset(_read_cells(block) | in_store.cell_refs() | {state_cell})

    # Partition read cells into enumerable (finite, non-bottom) vs saturating.
    product_cells: list[LocationRef] = []
    value_lists: list[tuple[int, ...]] = []
    has_top_read = False
    for cell in sorted(tracked, key=lambda c: (c.kind.value, c.key, c.width)):
        sv = in_store.get(cell)
        if sv.is_top:
            has_top_read = True
            continue
        if sv.is_bottom:
            continue  # unreachable read cell: fold with it absent
        product_cells.append(cell)
        value_lists.append(tuple(sorted(sv.constants)))

    product_size = 1
    for vals in value_lists:
        product_size *= len(vals)
    over_cap = product_size > max_product

    out_accum: dict[LocationRef, StateValue] = {}

    def _merge(partial: dict[LocationRef, StateValue], *, force_top: bool) -> None:
        for cell, sv in partial.items():
            value = StateValue.top() if force_top else sv
            existing = out_accum.get(cell)
            out_accum[cell] = value if existing is None else existing.join(value)

    if over_cap:
        # Cannot enumerate: fold the per-cell minimum (smallest constant each)
        # only to discover *which* cells the block writes, then mark them top.
        stk, reg = _store_to_scalar_maps(
            {c: vals[0] for c, vals in zip(product_cells, value_lists)}
        )
        out_stk, out_reg = block_evaluator(
            block, dict(stk), dict(reg), state_var_stkoff
        )
        _merge(_lift_scalar_maps(out_stk, out_reg, tracked), force_top=True)
    elif not value_lists:
        out_stk, out_reg = block_evaluator(block, {}, {}, state_var_stkoff)
        _merge(_lift_scalar_maps(out_stk, out_reg, tracked), force_top=False)
    else:
        for combo in product(*value_lists):
            assignment = dict(zip(product_cells, combo))
            stk, reg = _store_to_scalar_maps(assignment)
            out_stk, out_reg = block_evaluator(
                block, dict(stk), dict(reg), state_var_stkoff
            )
            _merge(_lift_scalar_maps(out_stk, out_reg, tracked), force_top=False)

    # A strong-update whose source the fold could not resolve makes the dest
    # UNKNOWN (top), not killed/stale: DEFFAI's data/MBA-obfuscated next-state.
    written = _written_cells(block)
    unresolved_writes = {c for c in written if c not in out_accum}

    # Pass through untouched in-store cells, EXCEPT cells the block overwrote
    # with an unresolved value (those become top, below).
    result: dict[LocationRef, StateValue] = dict(out_accum)
    for cell in in_store.cell_refs():
        if cell not in result and cell not in unresolved_writes:
            result[cell] = in_store.get(cell)
    for cell in unresolved_writes:
        result[cell] = StateValue.top()
    if has_top_read:
        for cell in tracked:
            if in_store.get(cell).is_top and cell not in out_accum:
                result[cell] = StateValue.top()
    return PowersetStore(result)


def _refine_arm(
    store: PowersetStore,
    cell: Optional[LocationRef],
    const: Optional[int],
    *,
    equal: bool,
) -> PowersetStore:
    """Refine ``cell`` in ``store`` by ``assume cell == const`` / ``!= const``.

    The taken / not-taken arm ``assume`` (worklist ``edge_refine`` semantics):
    :meth:`StateValue.meet_const` for the equal arm, :meth:`StateValue.exclude`
    for the not-equal arm.  Only *removes* infeasible values -- can shrink the
    cell to ``bottom`` (the arm is infeasible) but never invents a value.  A
    ``None`` cell / const (the compare did not name a tracked cell) is a no-op.
    """
    if cell is None or const is None:
        return store
    sv = store.get(cell)
    refined = sv.meet_const(const) if equal else sv.exclude(const)
    return store.set(cell, refined)


def transfer_block_set(
    block: BlockSnapshot,
    in_store: PowersetStore,
    *,
    state_cell: LocationRef,
    condvar_cells: frozenset[LocationRef] = frozenset(),
    block_evaluator: Optional[BlockEvaluator] = None,
    state_var_stkoff: Optional[int] = None,
    max_product: int = 256,
) -> dict[int, PowersetStore]:
    """Fold ``block`` set-valued; return ``{successor_serial -> out_store}``.

    * A 1-way block -> ``{succ: out_store}`` (the single successor).
    * A 2-way branch -> two arms ``{taken: out_taken, fallthrough: out_ft}``,
      EACH refined by the branch predicate on the condvar cell (``assume``).
    * A TABLE_JUMP tail -> one arm per ``switch_cases`` row, the state cell
      refined to that case's value set.
    * A 0-way / terminal block -> ``{}`` (no successors).

    ``state_cell`` is the dispatcher state variable's cell (always carried out
    even when only the block writes it).  ``condvar_cells`` are the condition
    variables the arms refine (the state cell is included implicitly for a
    compare against it).  ``block_evaluator`` defaults to the registry-backed
    scalar fold (:func:`scalar_block_evaluator`); ``state_var_stkoff`` defaults
    to the state cell's stack offset.

    Soundness: arm ``assume`` only removes infeasible values; the multi-value
    fold joins over a *bounded* concretization and degrades to ``top`` past the
    cap -- always over-approximating, never under.
    """
    if state_var_stkoff is None:
        state_var_stkoff = (
            int(state_cell.key) if state_cell.kind.name == "STACK" else 0
        )
    if block_evaluator is None:
        block_evaluator = scalar_block_evaluator(int(state_var_stkoff))

    out_store = _fold_block_set(
        block,
        in_store,
        block_evaluator=block_evaluator,
        state_var_stkoff=int(state_var_stkoff),
        state_cell=state_cell,
        max_product=max_product,
    )

    succs = tuple(block.succs)
    tail = block.tail

    # -- TABLE_JUMP (jtbl) fan-out -----------------------------------------
    if (
        tail is not None
        and tail.kind is InsnKind.TABLE_JUMP
        and _switch_cases(tail)
    ):
        return _transfer_switch(out_store, tail, state_cell)

    # -- 2-way conditional fork --------------------------------------------
    if len(succs) == 2 and tail is not None and tail.is_conditional_jump:
        taken, fallthrough = _arm_targets(block)
        if taken is not None and fallthrough is not None:
            pred = branch_predicate(tail)
            const, cmp_cell = _compare_const_and_cell(tail)
            if cmp_cell is None and pred in (PredicateKind.EQ, PredicateKind.NE):
                # The compare did not name a tracked cell directly; assume it is
                # the dispatcher state cell (the common ``s == K`` dispatch arm).
                cmp_cell = state_cell
            # Only an equality compare yields a sound per-arm const refinement
            # (meet_const / exclude); other predicates keep both arms unrefined.
            if pred is PredicateKind.EQ:
                eq_arm, ne_arm = taken, fallthrough
            elif pred is PredicateKind.NE:
                eq_arm, ne_arm = fallthrough, taken
            else:
                cmp_cell = None  # no equality semantics -> no refinement
                eq_arm, ne_arm = taken, fallthrough
            return {
                eq_arm: _refine_arm(out_store, cmp_cell, const, equal=True),
                ne_arm: _refine_arm(out_store, cmp_cell, const, equal=False),
            }

    # -- straight-line / unrefined fan-out ---------------------------------
    return {int(s): out_store for s in succs}


def _switch_cases(tail: InsnSnapshot) -> tuple[tuple[tuple[int, ...], int], ...]:
    """The ``(case_values, target)`` rows off a TABLE_JUMP tail, or ``()``.

    Read off the canonical ``Instruction.control.switch_cases`` (the projection
    collects the case table from whichever operand carries it -- ``l`` then
    ``d`` -- via ``_switch_cases_from``).  Each :class:`InstructionSwitchCase` is
    flattened back to the legacy ``(case_values, target)`` tuple shape the jtbl
    fan-out (:func:`_transfer_switch`) consumes; an empty ``values`` tuple is the
    default target.
    """
    control = project_instruction(tail).control
    if control is None or not control.switch_cases:
        return ()
    return tuple(
        (tuple(case.values), int(case.target)) for case in control.switch_cases
    )


def _transfer_switch(
    out_store: PowersetStore,
    tail: InsnSnapshot,
    state_cell: LocationRef,
) -> dict[int, PowersetStore]:
    """Fork a TABLE_JUMP: one arm per case row, state cell refined to the case set.

    Each row is ``(case_values, target_block)``; an empty ``case_values`` is the
    default target (state cell unrefined there -- it carries whatever the fold
    produced).  A non-default arm refines the state cell to the row's value set
    (``meet`` with the case values), so each handler context sees only its case.
    """
    arms: dict[int, PowersetStore] = {}
    for case_values, target in _switch_cases(tail):
        target = int(target)
        if not case_values:
            arms[target] = out_store  # default arm: unrefined
            continue
        case_set = StateValue.of_many(int(v) for v in case_values)
        refined = out_store.get(state_cell).meet(case_set)
        arm_store = out_store.set(state_cell, refined)
        existing = arms.get(target)
        arms[target] = arm_store if existing is None else _join_stores(existing, arm_store)
    return arms


def _join_stores(a: PowersetStore, b: PowersetStore) -> PowersetStore:
    return a.join(b)
