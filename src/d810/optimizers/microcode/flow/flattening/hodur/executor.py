"""Backward-compatible Hodur executor re-exports.

The canonical executor surface now lives in
``d810.optimizers.microcode.flow.flattening.engine.executor``.
"""
from __future__ import annotations

from contextlib import contextmanager

from d810.optimizers.microcode.flow.flattening.safeguards import (
    should_apply_bulk_cfg_modifications,
)

__all__ = ["should_apply_bulk_cfg_modifications"]


def _load_engine_executor_module():
    try:
        from d810.optimizers.microcode.flow.flattening.engine import executor as _engine_executor
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("ida"):
            raise AttributeError(
                "TransactionalExecutor is unavailable without IDA dependencies"
            ) from exc
        raise
    return _engine_executor


@contextmanager
def _compat_engine_globals(_engine_executor):
    previous = _engine_executor.should_apply_bulk_cfg_modifications
    _engine_executor.should_apply_bulk_cfg_modifications = (
        should_apply_bulk_cfg_modifications
    )
    try:
        yield
    finally:
        _engine_executor.should_apply_bulk_cfg_modifications = previous


def _build_compat_transactional_executor():
    _engine_executor = _load_engine_executor_module()
    base = _engine_executor.TransactionalExecutor

    class TransactionalExecutor(base):
        def execute_pipeline(self, pipeline, total_handlers):
            with _compat_engine_globals(_engine_executor):
                return super().execute_pipeline(pipeline, total_handlers)

        def execute_stage(
            self,
            fragment,
            total_handlers,
            cumulative_pre_cfg=None,
        ):
            with _compat_engine_globals(_engine_executor):
                return super().execute_stage(
                    fragment,
                    total_handlers,
                    cumulative_pre_cfg=cumulative_pre_cfg,
                )

    TransactionalExecutor.__module__ = __name__
    return TransactionalExecutor


def __getattr__(name: str):
    if name == "TransactionalExecutor":
        compat_cls = _build_compat_transactional_executor()
        globals()[name] = compat_cls
        return compat_cls
    _engine_executor = _load_engine_executor_module()
    return getattr(_engine_executor, name)
