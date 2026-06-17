"""Live Hex-Rays post-D810 capture and diagnostic subscribers."""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass

from d810.backends.hexrays.evidence.microcode_dump import mba_to_dict
from d810.core.logging import getLogger
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.settings import get_settings
from d810.core.typing import Any, Callable

logger = getLogger("D810.runtime.post_d810")


def _default_maturity_name(maturity: int) -> str:
    try:
        import ida_hexrays

        names = {
            ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
            ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
            ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
            ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
            ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
            ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
            ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
            ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
            ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
        }
        return names.get(maturity, f"MMAT_{maturity}")
    except ImportError:
        return f"MMAT_{maturity}"


@dataclass(eq=False, slots=True)
class HexRaysPostD810Runtime:
    """Owns post-D810 live Hex-Rays capture and probe subscribers."""

    recon_runtime: Any | None
    block_optimizer: Any
    settings_provider: Callable[[], Any] = get_settings
    maturity_name_provider: Callable[[int], str] = _default_maturity_name
    handoff_detector: Callable[..., Any] | None = None
    environ: Mapping[str, str] | None = None

    def _maturity_name(self, maturity: int) -> str:
        return self.maturity_name_provider(int(maturity))

    def capture_mba(
        self,
        mba: Any,
        maturity: int,
        snapshot: Any = None,
    ) -> None:
        """Write post-maturity MBA snapshot when configured via environment."""
        del snapshot
        settings = self.settings_provider()
        if settings.capture_post_maturity is None:
            return
        if int(maturity) != settings.capture_post_maturity:
            return
        capture_file = settings.capture_post_file
        try:
            data = mba_to_dict(mba)
            with open(capture_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            logger.info(
                "Post-D810 MBA captured at maturity %s -> %s (%d blocks)",
                self._maturity_name(maturity),
                capture_file,
                data.get("num_blocks", -1),
            )
        except Exception:
            logger.exception("Post-D810 capture failed")

    def capture_facts(
        self,
        mba: Any,
        maturity: int,
        snapshot: Any = None,
    ) -> None:
        """Capture maturity facts on the post-D810 snapshot."""
        if self.recon_runtime is None:
            return
        try:
            func_ea = int(getattr(mba, "entry_ea", 0) or 0)
            provider_phase = ProviderPhaseSnapshot(
                provider_name="hexrays_microcode",
                provider_level=int(maturity),
                friendly_provider_level=self._maturity_name(int(maturity)),
            )
            try:
                from d810.hexrays.fact_target import mba_to_fact_target

                target = mba_to_fact_target(mba)
            except Exception:
                logger.exception(
                    "Post-D810 fact target adaptation failed for func=0x%x; "
                    "skipping fact capture",
                    func_ea,
                )
                return
            self.recon_runtime.capture_maturity_facts(
                target,
                func_ea=func_ea,
                provider_phase=provider_phase,
                phase="post_d810",
                snapshot=snapshot,
            )
        except Exception:
            logger.exception("FactLifecycleRuntime post-D810 capture failed")

    def resolve_linearization_context(
        self,
        mba: Any,
        target_maturity: int,
    ) -> tuple[int | None, int | None]:
        """Resolve dispatcher/state-var context for post-D810 rendering."""
        entry_ea = int(getattr(mba, "entry_ea", 0) or 0)
        candidates = [
            rule
            for rule in getattr(self.block_optimizer, "cfg_rules", ())
            if type(rule).__name__ in ("StateMachineCffUnflattener",)
            and int(getattr(rule, "_last_func_ea", 0) or 0) == entry_ea
        ]

        def _try_rules(rules: list[Any]) -> tuple[int | None, int | None]:
            for rule in rules:
                dispatcher_serial: int | None = None
                dispatcher_ea = int(getattr(rule, "_last_dispatcher_ea", 0) or 0)
                if dispatcher_ea:
                    for i in range(int(getattr(mba, "qty", 0) or 0)):
                        blk = mba.get_mblock(i)
                        if (
                            blk is not None
                            and int(getattr(blk, "start", 0) or 0) == dispatcher_ea
                        ):
                            dispatcher_serial = int(getattr(blk, "serial", i))
                            break
                if dispatcher_serial is None:
                    raw_serial = int(getattr(rule, "_last_dispatcher_serial", -1) or -1)
                    if 0 <= raw_serial < int(getattr(mba, "qty", 0) or 0):
                        dispatcher_serial = raw_serial

                if dispatcher_serial is None:
                    continue

                state_var_stkoff: int | None = None
                try:
                    state_machine = getattr(rule, "state_machine", None)
                    state_var_stkoff = rule._get_effective_state_var_stkoff(state_machine)
                except Exception:
                    state_var_stkoff = None
                return dispatcher_serial, state_var_stkoff
            return None, None

        exact_maturity = [
            rule
            for rule in candidates
            if getattr(rule, "_current_tracked_maturity", None) is None
            or int(getattr(rule, "_current_tracked_maturity", 0)) == int(target_maturity)
        ]
        dispatcher_serial, state_var_stkoff = _try_rules(exact_maturity)
        if dispatcher_serial is not None:
            return dispatcher_serial, state_var_stkoff
        dispatcher_serial, state_var_stkoff = _try_rules(candidates)
        if dispatcher_serial is not None:
            return dispatcher_serial, state_var_stkoff
        return None, None

    def attach_rendered_program(
        self,
        mba: Any,
        maturity: int,
        snapshot: Any = None,
    ) -> None:
        """Attach a rendered linearized program to a post-D810 snapshot."""
        settings = self.settings_provider()
        if settings.capture_post_maturity is None:
            return
        target_mat = settings.capture_post_maturity
        if int(maturity) != target_mat:
            return
        if int(getattr(mba, "qty", 0) or 0) <= 0:
            return
        if snapshot is None:
            return

        try:
            from d810.analyses.control_flow.linearized_state_dag import (
                BoundaryInlineMode,
                ProgramCommentMode,
                ProgramRenderStrategy,
                RenderOrderStrategy,
            )
            from d810.backends.hexrays.evidence.microcode_dump import (
                build_live_linearized_program,
                resolve_dispatcher_context_for_linearized_program,
            )
            from d810.core.observability_recon import observe_rendered_program

            dispatcher_serial, state_var_stkoff = self.resolve_linearization_context(
                mba,
                int(maturity),
            )
            if dispatcher_serial is None:
                dispatcher_serial, state_var_stkoff = (
                    resolve_dispatcher_context_for_linearized_program(mba)
                )

            if dispatcher_serial is None or dispatcher_serial < 0:
                logger.debug(
                    "post_d810 linearized program skipped: no trusted dispatcher context "
                    "for func=0x%x maturity=%s",
                    int(getattr(mba, "entry_ea", 0) or 0),
                    self._maturity_name(int(maturity)),
                )
                return

            program = build_live_linearized_program(
                mba,
                dispatcher_serial,
                state_var_stkoff=state_var_stkoff,
                order_strategy=RenderOrderStrategy.SEMANTIC,
                program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
                boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
                comment_mode=ProgramCommentMode.MINIMAL,
            )
            observe_rendered_program(snapshot, program)
        except Exception:
            logger.warning(
                "post_d810 rendered program attach failed for func=0x%x maturity=%s",
                int(getattr(mba, "entry_ea", 0) or 0),
                self._maturity_name(int(maturity)),
                exc_info=True,
            )

    def probe_glbopt_dce(
        self,
        mba: Any,
        maturity: int,
        snapshot: Any = None,
    ) -> None:
        """Run the GLBOPT DCE probe against byte-emit EAs from the environment."""
        del snapshot
        environ = self.environ if self.environ is not None else os.environ
        raw = environ.get("D810_GLBOPT_DCE_EAS", "")
        if not raw:
            return
        try:
            import ida_hexrays as _hx
            if int(maturity) != int(_hx.MMAT_LOCOPT):
                return
        except Exception:
            pass
        try:
            byte_emit_eas = [int(s.strip(), 0) for s in raw.split(",") if s.strip()]
        except ValueError:
            logger.warning(
                "D810_GLBOPT_DCE_EAS=%r is not parseable as comma-separated hex EAs",
                raw,
            )
            return
        if int(getattr(mba, "qty", 0) or 0) <= 0:
            return
        try:
            from d810.hexrays.diagnostics.glbopt_dce_probe import probe_byte_emit_dce

            lines = probe_byte_emit_dce(mba, byte_emit_eas)
        except Exception:
            logger.warning(
                "glbopt DCE probe failed for func=0x%x maturity=%s",
                int(getattr(mba, "entry_ea", 0) or 0),
                self._maturity_name(int(maturity)),
                exc_info=True,
            )
            return
        report = "\n".join(lines)
        logger.warning(
            "\n[GLBOPT_DCE_PROBE func=0x%x maturity=%s]\n%s",
            int(getattr(mba, "entry_ea", 0) or 0),
            self._maturity_name(int(maturity)),
            report,
        )

    def validate_handoff(
        self,
        mba: Any,
        maturity: int,
        snapshot: Any = None,
    ) -> None:
        """Log diagnostic violations when post-D810 compaction orphans live uses."""
        if snapshot is None:
            return
        if self.handoff_detector is None:
            return
        try:
            from d810.core.observability import (
                get_active_diag_conn,
                resolve_snapshot_id_for,
            )

            diag_db = get_active_diag_conn(int(getattr(mba, "entry_ea", 0) or 0))
            snapshot_id = resolve_snapshot_id_for(snapshot)
            if diag_db is None or snapshot_id is None:
                return
            violations = self.handoff_detector(
                diag_db,
                func_ea_i64=int(getattr(mba, "entry_ea", 0) or 0),
                maturity_name=self._maturity_name(int(maturity)),
                post_snapshot_id=int(snapshot_id),
            )
            for violation in violations:
                missing_offsets = ", ".join(
                    f"0x{offset:X}" for offset in violation.missing_def_offsets
                )
                logger.warning(
                    "post_d810 handoff invalid for %s: snapshot %d -> %d left live uses "
                    "without defs for offsets [%s]; uses=%s defs=%s",
                    violation.bundle_name,
                    violation.pre_snapshot_id,
                    violation.post_snapshot_id,
                    missing_offsets,
                    list(violation.use_sites),
                    list(violation.def_sites),
                )
        except Exception:
            logger.debug("post_d810 handoff validation failed", exc_info=True)
