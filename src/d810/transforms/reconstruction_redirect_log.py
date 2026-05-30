"""Diagnostic-only instrumentation for reconstruction edge-redirect emissions.

Emits ``RECONSTRUCTION_REDIRECT_ATTEMPT:`` log lines at each planner site
that queues a dispatcher-fan-in → handler redirect. The log captures
``phase``, ``src``, ``old_target``, ``new_target``, ``state`` and an
``target_is_semantic_handler`` annotation so post-hoc analysis can join
against ``state_write_reconstruction_post_apply`` and
``MMAT_GLBOPT1_post_d810`` snapshots in the diag SQLite DB to decide
whether any given attempt survived to affect final topology.

This module is intentionally diagnostic-only. An earlier experiment
(``D810_PRESERVE_DISPATCHER_FOR_UNLINEARIZED``) suppressed these emissions
when ``new_target`` was a semantic DAG handler entry; measurements on
``sub_7FFD3338C040`` showed the gate was ineffective (``post_d810`` block
count 49 gated vs 52 un-gated — the 233→~50 collapse happens entirely
downstream of the sites this module observes, inside Hex-Rays's own pass
chain after d810 returns). The gate has been removed. Do not reintroduce
a behavior branch from this module without new evidence that the
``post_apply`` → ``post_d810`` collapse mechanism is at the sites logged
here.

The log line says ``ATTEMPT`` specifically because the presence of a line
does **not** prove the edge change persisted in the final graph — a
separate redirect path may emit the same edge, or a downstream Hex-Rays
pass may merge/delete either end of the edge. Use the diag DB to
distinguish "attempted" from "final topology changed".
"""
from __future__ import annotations

from d810.core import logging

logger = logging.getLogger("D810.cfg.reconstruction_redirect_log", logging.DEBUG)


def target_is_semantic_handler(target_entry: int, dag: object) -> bool:
    """Return ``True`` if *target_entry* is a semantic DAG handler entry.

    A handler entry qualifies when some node in ``dag.nodes`` has
    ``node.entry_anchor == target_entry`` AND its ``node.key.state_const``
    is not ``None``. Alias/cleanup nodes (``state_const is None``) do not
    qualify. Returns ``False`` defensively when *dag* is ``None`` or lacks
    the ``nodes`` attribute.

    Used as pure annotation on redirect-attempt log lines — callers must
    not branch on it to alter emission behavior.
    """
    if dag is None:
        return False
    nodes = getattr(dag, "nodes", None)
    if not nodes:
        return False
    target = int(target_entry)
    for node in nodes:
        try:
            if int(node.entry_anchor) != target:
                continue
        except (TypeError, ValueError):
            continue
        key = getattr(node, "key", None)
        if key is None:
            continue
        if getattr(key, "state_const", None) is not None:
            return True
    return False


def log_redirect_attempt(
    *,
    phase: str,
    src: int,
    old_target: int,
    new_target: int,
    dag: object | None,
    state_const: int | None = None,
) -> None:
    """Emit one ``RECONSTRUCTION_REDIRECT_ATTEMPT:`` line.

    Log fields (space-separated, all ``key=value``):

    - ``src`` / ``old_target`` / ``new_target`` — the planner's intent
    - ``state`` — state constant of the owning edge, or ``None``
    - ``phase`` — emission site label (e.g. ``preheader_bridge``,
      ``dag_bridge``, ``lfg_preheader``, ``residual_handoff``)
    - ``target_is_semantic_handler`` — annotation; ``True`` when
      ``new_target`` is a DAG handler entry with a real state_const,
      ``False`` for aliases and non-handler targets

    Does not return a value. Callers must not branch on this log.
    """
    target_is_sh = target_is_semantic_handler(int(new_target), dag)
    state_hex = (
        "None"
        if state_const is None
        else f"0x{int(state_const) & 0xFFFFFFFFFFFFFFFF:x}"
    )
    logger.info(
        "RECONSTRUCTION_REDIRECT_ATTEMPT: src=%d old_target=%d new_target=%d state=%s phase=%s target_is_semantic_handler=%s",
        int(src),
        int(old_target),
        int(new_target),
        state_hex,
        phase,
        bool(target_is_sh),
    )


__all__ = [
    "target_is_semantic_handler",
    "log_redirect_attempt",
]
