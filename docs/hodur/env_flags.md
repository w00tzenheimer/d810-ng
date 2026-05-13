# Hodur Environment Flags

This is the manifest for Hodur/unflattening environment flags that affect
strategy selection, HCC behavior, reconstruction experiments, and diagnostics.
Keep this file updated whenever a new `D810_*` flag is added to this area.

## Live Hodur Strategy Selection

| Variable | Default | Effect |
| --- | --- | --- |
| `D810_DISABLE_HANDLER_CHAIN_COMPOSER=1` | off | Force-disables HCC. Use only for archaeology or regression isolation. |
| `D810_ENABLE_HANDLER_CHAIN_COMPOSER=0` | unset | Also force-disables HCC. `=1` is still accepted for old repro commands, but HCC is already default-on. |
| `D810_HODUR_ENABLE_SEMANTIC_STRUCTURED_REGION=1` | off | Opts the older `SemanticStructuredRegionStrategy` back into the live Hodur strategy list. Current `sub_7FFD3338C040` metrics are unchanged with it on. |
| `D810_HODUR_ONLY=ClassA,ClassB` | unset | Runs only the listed Hodur strategy classes after default registration. Useful for bisects. |
| `D810_HODUR_SKIP=ClassA,ClassB` | unset | Skips listed Hodur strategy classes after `D810_HODUR_ONLY` filtering. |
| `D810_RECON_ENABLE_STANDALONE_SRW=1` | off | Re-enables standalone `StateWriteReconstructionStrategy`. HCC owns SWR-style orchestration by default. |
| `D810_RECON_SKIP_SRW_STRATEGY=1` | unset | Force-disables standalone SRW even when `D810_RECON_ENABLE_STANDALONE_SRW=1` is set. |

## HCC Feature Flags

These are part of the default live HCC profile unless explicitly disabled.

| Variable | Default | Effect |
| --- | --- | --- |
| `D810_HCC_TAIL_EXTENSION=0/1` | `1` | Preserves multi-pred local convergence and redirects only the semantic exit. This is the SSA-safe replacement for convergence duplication. |
| `D810_HCC_CALL_BARRIER=0/1` | `1` | Preserves `m_call`/`m_icall` blocks as original anchors and routes semantic flow around them instead of copying calls into `InsertBlock` bodies. |
| `D810_HCC_CHAINED_GUARDED_SOURCE=0/1` | `1` | Keeps the guarded upstream source in the real CFG for chained call anchors instead of copying away the guard/reaching-def context. |
| `D810_HCC_USE_DEF_VETO=0/1` | `1` | Planner-level veto for direct redirects that would sever reaching definitions. Disable only for controlled negative tests. |

## HCC Experimental Flags

These are not part of the default live profile.

| Variable | Default | Effect |
| --- | --- | --- |
| `D810_HCC_REGION_FUSION=1` | off | Enables plain `FUSABLE_LINEAR` region fusion. Useful for experiments but not required for the current default profile. |
| `D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION=1` | off | Enables per-pred convergence body cloning. This is SSA-hostile and retained only as evidence/debug tooling. Do not treat it as fallback architecture. |

## Linearized Flow Graph / Reconstruction Gates

| Variable | Default | Effect |
| --- | --- | --- |
| `D810_LFG_BOUNDED_POSTPROCESS=0/1` | `1` | Enables bounded postprocessing in `linearized_flow_graph`. Set `0` to disable. |
| `D810_PREFER_DIRECT_FOR_TRANSITION=1` | off | Prefer direct reconstruction emission for non-conditional DAG edges where supported. |
| `D810_RECON_SKIP_PRIMARY=1` | off | Skip primary reconstruction contribution in contribution/bisect runs. |
| `D810_RECON_SKIP_FRONTIER=1` | off | Skip frontier contribution. |
| `D810_RECON_SKIP_FORCE_EDGE=1` | off | Skip force-edge contribution. |
| `D810_RECON_SKIP_NARROW_BRANCH_LOCAL=1` | off | Skip narrow branch-local contribution. |
| `D810_RECON_SKIP_MISSING_VIA_PRED=1` | off | Skip missing-via-pred repair contribution. |
| `D810_RECON_SKIP_RESIDUAL_ALIAS=1` | off | Skip residual alias repair contribution. |
| `D810_RECON_SKIP_ISLAND_RESCUE=1` | off | Skip entry-island rescue contribution. |
| `D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS=1` | off | Relaxes late-clone shared-block constraints. Experimental. |
| `D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS=1` | off | Forces per-pred shared block preservation. Experimental. |
| `D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS=1` | off | Forces primary shared-block cloning. Experimental. |

## Deferred Modifier / CFG Mutation Diagnostics

| Variable | Default | Effect |
| --- | --- | --- |
| `D810_TRACE_MOD_CONSTRUCTION=1` | off | Logs graph-modification construction. Preferred over the legacy alias below. |
| `D810_TRACE_REDIRECT_GOTO_CONSTRUCTION=1` | off | Legacy alias for redirect/mod-construction tracing. |
| `D810_TRACE_CONDITIONAL_REDIRECT=1` | off | Traces conditional redirect handling in deferred mutation code. |
| `D810_DEFERRED_TRANSACTIONAL=1` | off | Enables transactional deferred mutation behavior where supported. |
| `D810_DEFERRED_STAGED_ATOMIC=1` | off | Enables staged atomic deferred mutation behavior where supported. |
| `D810_DEFERRED_PREVERIFY=1` | off | Runs preverification before applying deferred modifications. |
| `D810_DEFERRED_VERIFY_EACH=1` | off | Verifies after each deferred modification. |
| `D810_DEFERRED_ROLLBACK_ON_VERIFY_FAILURE=1` | off | Rolls back when per-mod verification fails. |
| `D810_DEFERRED_CONTINUE_ON_VERIFY_FAILURE=1` | off | Continues after a verification failure. |
| `D810_DEFERRED_MAX_APPLY=N` | unset | Caps number of deferred modifications applied. Useful for bisection. |
| `D810_DEFERRED_SKIP_EDGES=A:B,C:D` | unset | Skips specific edge rewrites while applying block modifications. |
| `D810_BISECT_SKIP=A:B,C:D` | unset | Older edge-skip bisection hook. |
| `D810_DEFERRED_WATCH_EDGE=A:B` / `D810_DEFERRED_WATCH_EDGES=A:B,C:D` | unset | Watches specific edge transitions. |
| `D810_DEFERRED_WATCH_BLOCKS=A,B` | unset | Logs watched block state after deferred modifications. |
| `D810_DEFERRED_DIAG_PHASES=1` | off | Captures diag DB snapshots at deferred mutation phases; most useful with watched blocks. |
| `D810_DEFERRED_SCAN_STALE_SERIALS=1` | off | Scans for stale serial references during deferred mutation debugging. |

## Diagnostics and Dumping

| Variable | Default | Effect |
| --- | --- | --- |
| `D810_DEBUG_LOGGING=1` | off | Sets d810 loggers to debug level. The Docker runner forwards this via `--enable-debug-logging`. |
| `D810_DUMP_ALL_LINEARIZED_PROGRAMS=1` | off | Dumps all linearized program variants instead of only the default. |
| `D810_DIAG_FULL_COVERAGE_CHAIN=1` | off | Enables the SCC/full-coverage chain diagnostic probe. |
| `D810_FENCE_INSN_OPT_AT_GLBOPT1=1` | off | Fences instruction optimizers at GLBOPT1 for causality tests. |
| `D810_FORCE_BLK129_TO_BLK130=1` | off | Debug-only force edge used during the `sub_7FFD3338C040` investigation. |

## Docker Runner Pass-through

`tools/scripts/run_system_tests_docker.sh` forwards the Hodur/HCC/recon flags
listed above into the container. If a new flag must be usable in Docker E2E
runs, add it to the pass-through list there and to this manifest in the same
commit.
