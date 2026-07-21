from pathlib import Path

from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetBoundaryPorts,
    make_resolver_cut_boundary_port,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisFacts,
    NativePreanalysisSessionState,
    PreoptUnionPreparationResult,
)
from d810.analyses.control_flow.native_semantic_closure import NativeCfg
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
)
from tests.native_preanalysis import make_native_key

from tools.scripts.rhad_investigation.session_probe_evidence import (
    capture_preopt_union_preparation,
    latest_preopt_union_preparation,
    native_preanalysis_boundary_port_count,
)


_PROBE = (
    Path(__file__).resolve().parents[3]
    / "tools"
    / "scripts"
    / "rhad_investigation"
    / "probe_transfer_function.py"
)


def test_preopt_union_preparation_survives_live_session_cleanup() -> None:
    key = make_native_key()
    preparation = PreoptUnionPreparationResult(0x401000, True, True)
    native_preanalysis = NativePreanalysisSessionState()
    state = ResolverSessionState(native_preanalysis=native_preanalysis, native_key=key)
    captured: list[object] = []

    assert native_preanalysis.set_preopt_union_preparation(key, preparation)
    capture_preopt_union_preparation(state, captured)
    assert native_preanalysis.set_preopt_union_preparation(key, None)

    assert latest_preopt_union_preparation(state, captured) is preparation


def test_transfer_probe_uses_direct_execution_safe_sibling_import() -> None:
    source = _PROBE.read_text(encoding="utf-8")

    assert "from session_probe_evidence import (" in source
    assert ".extensions" not in source


def test_boundary_port_count_reads_canonical_session_facts_after_cleanup() -> None:
    key = make_native_key()
    ports = DetachedSnippetBoundaryPorts(
        direct=(
            make_resolver_cut_boundary_port(
                source_block_ea=0x401000,
                source_instruction_ea=0x401004,
                target_ea=0x402000,
                source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                provenance="test",
            ),
            make_resolver_cut_boundary_port(
                source_block_ea=0x401100,
                source_instruction_ea=0x401104,
                target_ea=0x402100,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                provenance="test",
            ),
        ),
        conditional=(),
    )
    native_preanalysis = NativePreanalysisSessionState(
        facts=NativePreanalysisFacts(
            key=key,
            native_cfg=NativeCfg({}),
            semantic_closure=None,
            transfers=(),
            boundary_ports=ports,
        )
    )
    state = ResolverSessionState(native_preanalysis=native_preanalysis, native_key=key)

    assert native_preanalysis_boundary_port_count(state) == 2
