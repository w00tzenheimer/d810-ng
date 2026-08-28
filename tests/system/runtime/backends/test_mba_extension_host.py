from __future__ import annotations

import ast
import json
from types import MappingProxyType, SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends.mba import extension_host  # noqa: E402
from d810.backends.mba.extension_host import native_mba_host_services  # noqa: E402
from d810.backends.mba.cross_block_preparation import (  # noqa: E402
    PreparedCrossBlockAst,
)
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot  # noqa: E402
from d810.mba.typed_term import TypedBvTerm, term_fingerprint  # noqa: E402
from d810.mba.extension_api import (  # noqa: E402
    atomize_native_candidate,
    reconstruct_native_provider_result,
)
from d810.core.function_execution_identity import (  # noqa: E402
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import PluginIdentity  # noqa: E402
from d810.mba.bounded_synthesis import CERTIFICATION_WIDTHS  # noqa: E402
from d810.mba.discovery_models import DiscoveryAttempt  # noqa: E402
from d810.mba.discovery_miner import DiscoveryMiner, materialize_proposal  # noqa: E402
from d810.mba.discovery_store import (  # noqa: E402
    MbaDiscoveryStore,
    decode_proposal_payload,
)
from d810.mba.provider_outcome import (  # noqa: E402
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.mba.provider_routing import MbaProviderKind  # noqa: E402


def _leaf(name: str, register: int, size: int = 4):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    return leaf


def _constant(value: int, size: int = 4):
    constant = ast_dispatcher.AstConstant(str(value), value, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=value)
    constant.dest_size = size
    return constant


def _node(opcode: int, left, right=None, size: int = 4):
    node = ast_dispatcher.AstNode(opcode, left, right)
    node.dest_size = size
    return node


def _instruction(ast, *, ea: int = 0x401000, destination_size: int = 4):
    destination = _leaf("out", 7, destination_size).create_mop(ea)
    return ast.create_minsn(ea, destination)


def _fake_native_residual_instruction(*, ea: int = 0x401000):
    """Build a detached native-shaped instruction for capture_instruction."""

    operations = {
        "add": ida_hexrays.m_add,
        "and": ida_hexrays.m_and,
        "bnot": ida_hexrays.m_bnot,
        "mul": ida_hexrays.m_mul,
        "sub": ida_hexrays.m_sub,
        "xor": ida_hexrays.m_xor,
    }

    def leaf(reg: int):
        return SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=reg)

    def constant(value: int):
        return SimpleNamespace(
            t=ida_hexrays.mop_n,
            size=4,
            nnn=SimpleNamespace(value=value),
        )

    def instruction(operation: str, left, right=None):
        return SimpleNamespace(
            ea=ea,
            opcode=operations[operation],
            l=left,
            r=right if right is not None else SimpleNamespace(t=ida_hexrays.mop_z, size=4),
            d=SimpleNamespace(t=ida_hexrays.mop_z, size=4),
        )

    def nested(operation: str, left, right=None):
        return SimpleNamespace(
            t=ida_hexrays.mop_d,
            size=4,
            d=instruction(operation, left, right),
        )

    def masked():
        return nested("and", leaf(2), constant(0xFFFFFBFB))

    x = leaf(1)
    top = instruction(
        "add",
        nested(
            "sub",
            nested("xor", x, masked()),
            nested(
                "add",
                nested("and", leaf(1), masked()),
                nested(
                    "mul",
                    constant(2),
                    nested("and", masked(), nested("bnot", leaf(1))),
                ),
            ),
        ),
        nested("mul", constant(2), masked()),
    )
    top.d = SimpleNamespace(t=ida_hexrays.mop_r, size=4, r=7)
    return top


def _residual_source_ast():
    def x():
        return _leaf("v17", 1)

    def masked():
        return _node(ida_hexrays.m_and, _leaf("v135", 2), _constant(0xFFFFFBFB))

    return _node(
        ida_hexrays.m_add,
        _node(
            ida_hexrays.m_sub,
            _node(ida_hexrays.m_xor, x(), masked()),
            _node(
                ida_hexrays.m_add,
                _node(ida_hexrays.m_and, x(), masked()),
                _node(
                    ida_hexrays.m_mul,
                    _constant(2),
                    _node(
                        ida_hexrays.m_and,
                        masked(),
                        _node(ida_hexrays.m_bnot, x()),
                    ),
                ),
            ),
        ),
        _node(ida_hexrays.m_mul, _constant(2), masked()),
    )


def _walk_terms(term):
    yield term
    for child in term.children:
        yield from _walk_terms(child)


def _instruction_shape(instruction):
    return (
        instruction.opcode,
        instruction.d.t,
        instruction.d.size,
        instruction.l.t,
        instruction.l.size,
        instruction.r.t,
        instruction.r.size,
    )


@pytest.mark.usefixtures("libobfuscated_setup")
class TestNativeMbaExtensionHost:
    binary_name = "libobfuscated.dll"

    def test_maturity_adapter_resolves_global_optimized(self):
        host = native_mba_host_services()

        assert host.maturities_for_names(["GLOBAL_OPTIMIZED"]) == (
            ida_hexrays.MMAT_GLBOPT2,
        )

        with pytest.raises(ValueError, match="IRMaturity names"):
            host.maturities_for_names(["MMAT_GLBOPT2"])

    def test_capture_instruction_preserves_width_terms_and_native_identity(self):
        host = native_mba_host_services()
        source = _node(
            ida_hexrays.m_add,
            _leaf("x", 1),
            _constant(7),
        )
        instruction = _instruction(source)

        candidate = host.capture_instruction(instruction)

        assert candidate is not None
        assert candidate.destination_size == 4
        assert candidate.term.width == 32
        assert candidate.raw_term is not None
        assert candidate.profile.width_bits == 32
        assert candidate.native_context is not None

    def test_fixed_shift_capture_keeps_literal_count(self):
        host = native_mba_host_services()
        source = _node(
            ida_hexrays.m_shl,
            _leaf("x", 1),
            _constant(5, size=1),
        )
        source.dest_size = 4
        candidate = host.capture_instruction(_instruction(source))

        assert candidate is not None
        assert candidate.term.operation == "shl"
        assert candidate.term.shift_count == 5

    def test_cross_block_preparation_retains_source_context(self, monkeypatch):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        candidate = host.capture_ast(source, destination_size=4)
        original_context = candidate.native_context

        def prepared(*_args):
            return PreparedCrossBlockAst(
                ast=source.clone(),
                substitutions=1,
                environment=MappingProxyType({}),
                known_constants=MappingProxyType({}),
            )

        monkeypatch.setattr(
            extension_host, "prepare_ast_with_cross_block_constants", prepared
        )
        result = host.prepare_cross_block(
            candidate,
            block=SimpleNamespace(mba=object()),
            instruction=object(),
            use_constants=True,
            use_def_use=False,
        )

        assert result.native_context is not original_context
        assert result.native_context.source_context is original_context
        assert result.raw_term is not None

    def test_leaf_root_rebuild_and_native_proof(self):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        source.dst_mop = _leaf("out", 7).create_mop(0x401000)
        candidate = host.capture_ast(source, destination_size=4)
        assert candidate.raw_term is not None
        leaf = next(
            node
            for node in (
                candidate.raw_term.children if candidate.raw_term.operation else ()
            )
            if node.leaf_key is not None
        )

        reconstruction = host.rebuild(candidate, leaf)

        assert reconstruction is not None
        assert reconstruction.replacement_ast is not None
        assert reconstruction.replacement_instruction is not None
        assert host.prove(
            candidate,
            reconstruction,
            certificate=None,
            known_constants=None,
        )

    def test_proof_timeout_is_forwarded_without_changing_default(self, monkeypatch):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        source.dst_mop = _leaf("out", 7).create_mop(0x401000)
        candidate = host.capture_ast(source, destination_size=4)
        leaf = next(node for node in candidate.raw_term.children if node.leaf_key)
        reconstruction = host.rebuild(candidate, leaf)
        assert reconstruction is not None
        forwarded: list[int] = []

        def prove(_original, _replacement, *, width, timeout_ms, **_kwargs):
            assert width == 32
            forwarded.append(timeout_ms)
            return True

        monkeypatch.setattr(extension_host, "prove_native_ast_equivalence", prove)

        assert host.prove(
            candidate,
            reconstruction,
            certificate=None,
            known_constants=None,
        )
        assert host.prove(
            candidate,
            reconstruction,
            certificate=None,
            known_constants=None,
            proof_timeout_ms=250,
        )
        assert forwarded == [50, 250]

    def test_nested_expression_rebuild_preserves_legacy_move_shape(self):
        """Nested optinsn expressions have mop_z destinations by design.

        The pre-extraction handler materialized these ASTs as an m_mov whose
        source is the rebuilt expression.  Calling AstNode.create_minsn()
        directly produces an operation instruction with a mop_z destination,
        which is the wrong API shape for the outer optinsn swap and is rejected
        by the host's top-level destination validator.
        """

        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        instruction = source.create_minsn(0x401000)
        assert instruction.d.t == ida_hexrays.mop_z
        candidate = host.capture_instruction(instruction)
        assert candidate is not None
        assert candidate.raw_term is not None
        leaf = next(
            node for node in candidate.raw_term.children if node.leaf_key is not None
        )

        reconstruction = host.rebuild(candidate, leaf)

        assert reconstruction is not None
        replacement = reconstruction.replacement_instruction
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.d.t == ida_hexrays.mop_z
        assert replacement.d.size == 4
        assert replacement.l.t == ida_hexrays.mop_r

    def test_rebuild_rejects_ast_candidate_without_destination(self):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        candidate = host.capture_ast(source, destination_size=4)
        assert candidate.raw_term is not None
        leaf = next(
            node for node in candidate.raw_term.children if node.leaf_key is not None
        )

        assert host.rebuild(candidate, leaf) is None

    def test_rebuild_ast_does_not_require_mutation_destination(self):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        candidate = host.capture_ast(source, destination_size=4)
        assert candidate.raw_term is not None
        leaf = next(
            node for node in candidate.raw_term.children if node.leaf_key is not None
        )

        rebuilt = host.rebuild_ast(candidate, leaf)

        assert rebuilt is not None

    def test_prove_ast_does_not_require_mutation_destination(self):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        candidate = host.capture_ast(source, destination_size=4)

        assert host.prove_ast(
            candidate,
            source.clone(),
            certificate=None,
            known_constants=None,
        )

    def test_rebuild_rejects_destination_copy_failure(self, monkeypatch):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        source.dst_mop = _leaf("out", 7).create_mop(0x401000)
        candidate = host.capture_ast(source, destination_size=4)
        assert candidate.raw_term is not None
        leaf = next(
            node for node in candidate.raw_term.children if node.leaf_key is not None
        )
        monkeypatch.setattr(
            extension_host, "_copy_destination", lambda _destination: None
        )

        assert host.rebuild(candidate, leaf) is None

    def test_provider_shaped_atomization_restoration_and_fail_closed_proof(
        self, monkeypatch
    ):
        host = native_mba_host_services()
        repeated = _node(ida_hexrays.m_and, _leaf("y", 2), _constant(0xFFFFFBFB))
        source = _node(
            ida_hexrays.m_or,
            _leaf("x", 1),
            _node(ida_hexrays.m_and, repeated, repeated),
        )
        source.dst_mop = _leaf("out", 7).create_mop(0x401000)
        instruction = _instruction(source)
        candidate = host.capture_instruction(instruction)
        assert candidate is not None
        original_shape = _instruction_shape(instruction)
        original_fingerprint = term_fingerprint(candidate.term)
        atomized = atomize_native_candidate(candidate)

        atom = next(
            node
            for node in _walk_terms(atomized.term)
            if node.operation is None
            and node.leaf_key is not None
            and node.leaf_key[0] == "d810.mba.atom.v1"
        )
        x = next(
            node
            for node in _walk_terms(atomized.term)
            if node.operation is None and node.leaf_key == ("mop", 1, 4, 1)
        )
        received: list[TypedBvTerm] = []

        def provider(term):
            received.append(term)
            return TypedBvTerm("or", term.width, children=(x, atom))

        reconstruction = reconstruct_native_provider_result(
            host,
            candidate,
            provider,
            proof_timeout_ms=250,
        )
        assert received == [atomized.term]
        assert atom in tuple(_walk_terms(received[0]))
        assert reconstruction is not None

        unknown_atom = TypedBvTerm(
            None,
            atomized.term.width,
            leaf_key=("d810.mba.atom.v1", 99, "unknown"),
        )
        with pytest.raises(ValueError, match="unknown reserved atom"):
            atomized.restore_replacement(
                TypedBvTerm("or", atomized.term.width, children=(x, unknown_atom))
            )

        rebuild_called = False

        def unexpected_rebuild(*_args, **_kwargs):
            nonlocal rebuild_called
            rebuild_called = True
            raise AssertionError("unknown atom reached host.rebuild")

        monkeypatch.setattr(host, "rebuild", unexpected_rebuild)
        assert (
            reconstruct_native_provider_result(
                host,
                candidate,
                lambda term: TypedBvTerm("or", term.width, children=(x, unknown_atom)),
            )
            is None
        )
        assert rebuild_called is False

        monkeypatch.undo()
        monkeypatch.setattr(
            extension_host, "prove_native_ast_equivalence", lambda *args, **kwargs: False
        )
        swaps: list[object] = []
        rejected = reconstruct_native_provider_result(
            host,
            candidate,
            provider,
            proof_timeout_ms=250,
        )
        if rejected is not None:
            swaps.append(rejected.replacement_instruction)
        assert rejected is None
        assert swaps == []
        assert _instruction_shape(instruction) == original_shape
        assert term_fingerprint(candidate.term) == original_fingerprint
        assert candidate.native_context.source_instruction is instruction

    def test_live_raw_capture_mines_sqlite_and_materializes_proof(self, tmp_path):
        host = native_mba_host_services()
        candidate = host.capture_instruction(_fake_native_residual_instruction())
        assert candidate is not None
        assert candidate.raw_term is not None
        identity = FunctionExecutionIdentity(
            input_identity="sha256:" + "a" * 64,
            input_identity_provenance="verified_loader_sha256",
            external_evidence_allowed=True,
            database_uuid="12345678-1234-5678-1234-567812345678",
            database_identity="live-extension-host",
            function_ea=0x401000,
            function_rva=0x1000,
            function_fingerprint="live-function",
            decompilation_session_id="12345678-1234-5678-1234-567812345679",
            top_level_epoch=1,
            maturity="ir.canonical",
            evidence_generation=1,
        )
        attempt = DiscoveryAttempt(
            attempt_uuid="12345678-1234-5678-1234-567812345680",
            context=MbaObservationContext(
                function_identity=identity,
                plugin_identity=PluginIdentity("egglog", "egglog", "1", "ida-test"),
                instruction_ea=0x401000,
                block_serial=1,
                block_ea=0x401000,
            ),
            raw_term=candidate.raw_term,
            canonical_term=candidate.term,
            outcome=MbaProviderOutcome(
                provider=MbaProviderKind.EGRAPH,
                status=ProviderOutcomeStatus.UNCHANGED,
                fingerprint=term_fingerprint(candidate.term),
                elapsed_ms=1.0,
            ),
            eligible_for_mining=True,
        )
        store = MbaDiscoveryStore(tmp_path / "live-discovery.sqlite3")
        try:
            assert store.record_attempt(attempt).status.value == "stored"
            claim = DiscoveryMiner(store).claim().claim
            assert claim is not None
            mined = DiscoveryMiner(store).mine_claim(claim)
            assert mined.status == "published", mined.reason
            assert mined.proposal_id is not None
            output = tmp_path / "live-review"
            materialize_proposal(store, mined.proposal_id, output)
            snapshot = store.proposal_snapshot(mined.proposal_id)
            assert snapshot is not None
            stem = snapshot.proposal.proposal_fingerprint
            source = (output / f"{stem}.rule.py").read_text()
            ast.parse(source)
            namespace = {}
            exec(compile(source, str(output / f"{stem}.rule.py"), "exec"), namespace)
            proposal = decode_proposal_payload(snapshot.proposal.proposal_payload)
            assert proposal.class_name in namespace
            fixture = json.loads((output / f"{stem}.fixture.json").read_text())
            assert fixture["proof_widths"] == list(CERTIFICATION_WIDTHS)
        finally:
            store.close()

    def test_mixed_width_capture_and_rebuild_fail_closed(self):
        host = native_mba_host_services()
        mixed = _node(ida_hexrays.m_add, _leaf("wide", 1, 4), _leaf("narrow", 2, 2))

        with pytest.raises(ValueError):
            host.capture_ast(mixed, destination_size=4)

        candidate = host.capture_ast(
            _node(ida_hexrays.m_add, _leaf("x", 1), _constant(1)), destination_size=4
        )
        wrong_width = TypedBvTerm(None, 64, value=0)
        assert host.rebuild(candidate, wrong_width) is None

    def test_persistence_is_json_safe_and_namespace_isolated(self):
        host = native_mba_host_services()
        left = host.persistence("extension-host-test-left")
        right = host.persistence("extension-host-test-right")
        left.delete("sample")
        right.delete("sample")

        payload = {"width": 32, "nested": {"items": [{"ok": True}]}}
        left.put_json("sample", payload)
        payload["nested"]["items"][0]["ok"] = False
        payload["nested"]["items"].append({"caller": "only"})

        stored = left.get_json("sample")
        assert stored["width"] == 32
        assert stored["nested"]["items"][0] == {"ok": True}
        assert len(stored["nested"]["items"]) == 1
        assert isinstance(stored["nested"]["items"], tuple)
        with pytest.raises(TypeError):
            stored["nested"]["items"][0]["ok"] = False
        assert right.get_json("sample") is None
        assert left.keys(prefix="sam") == ("sample",)
        assert right.keys() == ()

        for invalid in (
            {"nested": {1: "non-string key"}},
            {"nested": [{"nan": float("nan")}]},
            {"nested": [{"inf": float("inf")}]},
            {"nested": [{"neg_inf": float("-inf")}]},
            {"nested": [object()]},
        ):
            with pytest.raises(TypeError):
                left.put_json("invalid", invalid)

        left.delete("sample")
        assert left.get_json("sample") is None

    def test_persistence_rejects_cycles_on_put_and_malformed_reads(self, monkeypatch):
        host = native_mba_host_services()
        persistence = host.persistence("extension-host-cycle-test")

        direct_list = []
        direct_list.append(direct_list)
        indirect_list = []
        indirect_list_child = []
        indirect_list.append(indirect_list_child)
        indirect_list_child.append(indirect_list)
        direct_dict = {}
        direct_dict["self"] = direct_dict
        indirect_dict = {}
        indirect_dict_child = {}
        indirect_dict["child"] = indirect_dict_child
        indirect_dict_child["parent"] = indirect_dict

        for cyclic in (
            {"nested": direct_list},
            {"nested": indirect_list},
            direct_dict,
            indirect_dict,
        ):
            with pytest.raises(TypeError):
                persistence.put_json("cyclic", cyclic)

        malformed_list = []
        malformed_list.append(malformed_list)
        malformed_list_child = []
        malformed_list_indirect = [malformed_list_child]
        malformed_list_child.append(malformed_list_indirect)
        malformed_dict = {}
        malformed_dict["self"] = malformed_dict
        malformed_dict_child = {}
        malformed_dict_indirect = {"child": malformed_dict_child}
        malformed_dict_child["parent"] = malformed_dict_indirect

        for malformed in (
            {"nested": malformed_list},
            {"nested": malformed_list_indirect},
            malformed_dict,
            malformed_dict_indirect,
        ):
            monkeypatch.setattr(
                persistence._storage,
                "get_native_patch_blob",
                lambda _scope, _key, malformed=malformed: malformed,
            )
            assert persistence.get_json("malformed") is None
