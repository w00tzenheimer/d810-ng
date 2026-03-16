"""Topological (reverse-postorder) block-level constant environment computation.

Walks all blocks in reverse-postorder, running the emulator on each block's
instructions to build an OUT environment, then propagates to successor IN
environments via a conservative meet (drop on conflict).

Single forward pass only -- no fixpoint iteration. Handles DAG portions of
the CFG; back-edge values remain unresolved.

Returns ``dict[int, dict[tuple, int]]`` mapping block serial to a dict of
``{mop_key: constant_value}`` for all variables with known constant values
at block entry. Suitable as ``const_in_states`` for Strategy 2 in the
emulator.
"""
from __future__ import annotations

from d810.core.logging import getLogger

logger = getLogger(__name__)

# Sentinel for conflicting values at merge points.
_CONFLICT = object()

# Maximum number of blocks before we skip (performance bound).
_MAX_BLOCKS = 500


def compute_block_environments(mba: object) -> dict[int, dict[tuple, int]]:
    """Run emulator in topological order, return per-block IN environments.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (typed as ``object`` to
            avoid a hard import dependency on IDA at module level).

    Returns:
        Mapping from block_serial to ``{mop_key: int_value}`` for all
        variables with known constant values at block entry.  Returns
        an empty dict on any top-level failure.
    """
    try:
        import ida_hexrays  # noqa: F811
    except ImportError:
        return {}

    try:
        return _compute_block_environments_impl(mba, ida_hexrays)
    except Exception as exc:
        logger.warning("topo_eval: top-level failure: %s", exc)
        return {}


def _compute_block_environments_impl(
    mba: object,
    ida_hexrays: object,
) -> dict[int, dict[tuple, int]]:
    """Core implementation (separated for testability and clarity)."""
    # Lazy imports to avoid circular dependency:
    # topo_eval -> emulator -> (eval uses topo_eval lazily)
    from d810.evaluator.hexrays_microcode.emulator import (
        MicroCodeEnvironment,
        MicroCodeInterpreter,
    )
    from d810.errors import EmulationException
    from d810.hexrays.expr.p_ast import get_mop_key

    qty: int = mba.qty  # type: ignore[attr-defined]
    if qty > _MAX_BLOCKS:
        logger.info(
            "topo_eval: skipping (%d blocks > %d limit)", qty, _MAX_BLOCKS
        )
        return {}

    # ------------------------------------------------------------------ RPO
    rpo = _compute_rpo(mba, qty)

    # ------------------------------------------------------------------ walk
    # OUT envs: block_serial -> {mop_key: int_value}
    out_envs: dict[int, dict[tuple, int]] = {}
    # IN envs:  block_serial -> {mop_key: int_value}
    in_envs: dict[int, dict[tuple, int]] = {}

    for blk_serial in rpo:
        blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
        if blk is None:
            continue

        # ----- Build IN from predecessor OUTs via conservative meet -----
        in_env_map: dict[tuple, int | object] = {}
        preds = list(blk.predset)  # type: ignore[attr-defined]
        for pred_serial in preds:
            pred_out = out_envs.get(int(pred_serial))
            if pred_out is None:
                continue
            for mop_key, value in pred_out.items():
                existing = in_env_map.get(mop_key)
                if existing is None:
                    # First predecessor defining this key.
                    in_env_map[mop_key] = value
                elif existing is _CONFLICT:
                    # Already conflicted -- nothing to do.
                    pass
                elif existing != value:
                    # Conflict: different predecessors disagree.
                    in_env_map[mop_key] = _CONFLICT

        # Strip conflicts to get clean IN map.
        clean_in: dict[tuple, int] = {
            k: v for k, v in in_env_map.items() if v is not _CONFLICT  # type: ignore[arg-type]
        }
        in_envs[blk_serial] = clean_in

        # ----- Seed MicroCodeEnvironment with IN values -----
        env = MicroCodeEnvironment()
        interpreter = MicroCodeInterpreter(
            global_environment=env, symbolic_mode=False,
            const_in_states={},  # empty to prevent recursive topo_eval
        )
        _seed_environment(env, clean_in, blk, ida_hexrays)

        # ----- Walk all instructions in the block -----
        ins = blk.head  # type: ignore[attr-defined]
        while ins is not None:
            try:
                interpreter.eval_instruction(blk, ins, env)
            except (EmulationException, Exception):
                pass  # continue with partial env
            ins = ins.next  # type: ignore[attr-defined]

        # ----- Extract OUT env from the environment -----
        out_envs[blk_serial] = _extract_env(env, get_mop_key)

    return in_envs


def _compute_rpo(mba: object, qty: int) -> list[int]:
    """Compute reverse-postorder of the CFG.

    Uses a simple iterative DFS rather than ``mbl_graph_t.depth_first_postorder``
    to avoid needing ``ida_pro.intvec_t`` at module level.
    """
    if qty == 0:
        return []

    # Build adjacency from mba
    succs: dict[int, list[int]] = {}
    for serial in range(qty):
        blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        if blk is None:
            succs[serial] = []
            continue
        succs[serial] = [blk.succ(i) for i in range(blk.nsucc())]

    # Iterative DFS postorder
    visited: set[int] = set()
    postorder: list[int] = []
    # Stack entries: (node, expanded)
    stack: list[tuple[int, bool]] = [(0, False)]

    while stack:
        node, expanded = stack.pop()
        if node in visited and not expanded:
            continue
        if expanded:
            postorder.append(node)
            continue
        if node in visited:
            continue
        visited.add(node)
        stack.append((node, True))  # push post-visit marker
        for s in reversed(succs.get(node, [])):
            if s not in visited:
                stack.append((s, False))

    return list(reversed(postorder))


def _seed_environment(
    env: object,
    clean_in: dict[tuple, int],
    blk: object,
    ida_hexrays: object,
) -> None:
    """Seed the MicroCodeEnvironment with values from ``clean_in``.

    Each key in ``clean_in`` is a tuple produced by ``get_mop_key``. We
    reconstruct a temporary ``mop_t`` to call ``env.define(mop, value)``.

    Key format (from ``get_mop_key``):
    - ``(mop_r, size, mreg)`` for registers
    - ``(mop_S, size, stkoff)`` for stack variables
    """
    mop_r = ida_hexrays.mop_r  # type: ignore[attr-defined]
    mop_S = ida_hexrays.mop_S  # type: ignore[attr-defined]

    for mop_key, value in clean_in.items():
        if len(mop_key) < 3:
            continue
        mop_type = mop_key[0]
        mop_size = mop_key[1]
        try:
            tmp = ida_hexrays.mop_t()  # type: ignore[attr-defined]
            tmp.size = mop_size
            if mop_type == mop_r:
                tmp.t = mop_r
                tmp.r = mop_key[2]  # mreg
                env.define(tmp, value)  # type: ignore[attr-defined]
            elif mop_type == mop_S:
                tmp.t = mop_S
                # Create mnumber_t-like object for stack offset.
                tmp.create_stkvar(blk.mba, mop_key[2])  # type: ignore[attr-defined]
                tmp.size = mop_size
                env.define(tmp, value)  # type: ignore[attr-defined]
        except Exception:
            # Skip keys we can't reconstruct (mop_d, mop_v, etc.).
            continue


def _extract_env(
    env: object,
    get_mop_key: object,
) -> dict[tuple, int]:
    """Extract ``{mop_key: value}`` from a MicroCodeEnvironment."""
    result: dict[tuple, int] = {}
    for mop, value in env.mop_r_record.items():  # type: ignore[attr-defined]
        try:
            key = get_mop_key(mop)  # type: ignore[misc]
            result[key] = value
        except Exception:
            continue
    for mop, value in env.mop_S_record.items():  # type: ignore[attr-defined]
        try:
            key = get_mop_key(mop)  # type: ignore[misc]
            result[key] = value
        except Exception:
            continue
    return result
