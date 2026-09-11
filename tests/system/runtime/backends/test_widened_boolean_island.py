"""Native regressions for the 32-bit widened-boolean island seen in OLLVM R2.

The R2 witness retained the surrounding expressions, but not the complete raw
payload of the rejected subtree.  These tests therefore reconstruct the narrow
representative requested by the consumer: ``xdu.4(setnz.1(reg.4, #0.4))``.
"""

from __future__ import annotations

import hashlib
import json

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
idaapi = pytest.importorskip("idaapi")

import d810.backends.mba.hexrays_island as island_backend  # noqa: E402
from d810.backends.mba.ida import (  # noqa: E402
    IDAPatternAdapter,
    attach_selected_certified_catalogue_snapshot,
)
from d810.backends.mba.hexrays_island import (  # noqa: E402
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.backends.mba.native_z3 import prove_native_ast_equivalence  # noqa: E402
from d810.hexrays.expr import ast as ast_dispatcher  # noqa: E402
from d810.hexrays.ir.minsn_utils import minsn_to_ast  # noqa: E402
from d810.hexrays.ir.mop_snapshot import MopSnapshot, raw_mop_identity  # noqa: E402
from d810.mba.rules.bnot import (  # noqa: E402
    Bnot_FactorRule_5,
    BnotXor_FactorRule_1,
)
from d810.mba.certified_catalogue import (  # noqa: E402
    ShadowMatcherParityLedger,
    StructuralMatcherParityExpectation,
    make_structural_matcher_parity_certificate,
)
from d810.optimizers.microcode.instructions.pattern_matching.engine import (  # noqa: E402
    get_engine_info,
)
from tests.system.runtime.backends.test_ida_ac_matching import (  # noqa: E402
    _raw_number,
    _raw_register,
)
from tests.system.runtime.conftest import (  # noqa: E402
    gen_microcode_at_maturity,
    get_func_ea,
)


WIDTH_BYTES = 4
WIDTH_BITS = WIDTH_BYTES * 8
WITNESS_EA = 0x180013423
WITNESS_KEY = 0x03090ABA
R6_XDU_EA = 0x180013399
R6_COMPARISON_EA = 0x180013391
R6_LOAD_EA = 0x18001338E
R6_SEGMENT_REGISTER = 256
R6_SEGMENT_SIZE = 2
R6_SEGMENT_VALNUM = 250
R6_STACK_OFFSET = 696
R6_STACK_SIZE = 8
R6_STACK_VALNUM = 249


def _leaf(name: str, register: int, *, size: int = WIDTH_BYTES):
    leaf = ast_dispatcher.AstLeaf(name)
    leaf.mop = MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=register)
    leaf.dest_size = size
    leaf.proof_origin = ("widened-boolean-representative", name)
    return leaf


def _constant(value: int, *, size: int = WIDTH_BYTES):
    constant = ast_dispatcher.AstConstant(str(value), value, size)
    constant.mop = MopSnapshot(t=ida_hexrays.mop_n, size=size, value=value)
    constant.dest_size = size
    constant.proof_origin = ("widened-boolean-representative", value, size)
    return constant


def _node(opcode: int, left, right=None, *, size: int = WIDTH_BYTES):
    node = ast_dispatcher.AstNode(opcode, left, right)
    node.dest_size = size
    return node


def _widened_boolean(
    register: int,
    *,
    register_size: int = WIDTH_BYTES,
    zero_size: int = WIDTH_BYTES,
    comparison_opcode: int | None = None,
    comparison_value: int = 0,
    comparison_result_size: int = 1,
    extension_size: int = WIDTH_BYTES,
):
    comparison = _node(
        ida_hexrays.m_setnz if comparison_opcode is None else comparison_opcode,
        _leaf("predicate", register, size=register_size),
        _constant(comparison_value, size=zero_size),
        size=comparison_result_size,
    )
    return _node(ida_hexrays.m_xdu, comparison, size=extension_size)


def _witness_ast(
    kind: str,
    *,
    predicate_register: int,
    key: int = WITNESS_KEY,
    predicate=None,
):
    predicate_term = (
        _widened_boolean(predicate_register) if predicate is None else predicate
    )
    if kind == "bnot-xor":
        inner = _node(
            ida_hexrays.m_xor,
            _node(ida_hexrays.m_bnot, _leaf("x_0", 24)),
            _constant(key),
        )
        return _node(
            ida_hexrays.m_xor,
            _node(ida_hexrays.m_bnot, inner),
            _node(ida_hexrays.m_or, predicate_term, _constant(key)),
        )
    if kind == "bnot-factor":
        return _node(
            ida_hexrays.m_bnot,
            _node(
                ida_hexrays.m_xor,
                _node(ida_hexrays.m_or, predicate_term, _constant(key)),
                _node(
                    ida_hexrays.m_bnot,
                    _node(
                        ida_hexrays.m_xor,
                        _leaf("x_8", 80),
                        _constant(key),
                    ),
                ),
            ),
        )
    raise AssertionError(f"unknown witness kind: {kind}")


def _materialize(source, *, destination_register: int = 96):
    source.ea = WITNESS_EA
    destination = _raw_register(destination_register, size=WIDTH_BYTES)
    source.dst_mop = destination
    instruction = source.create_minsn(WITNESS_EA, destination)
    candidate = minsn_to_ast(instruction)
    assert candidate is not None
    return instruction, candidate


def _instruction_mop(instruction):
    mop = ida_hexrays.mop_t()
    mop.create_from_insn(instruction)
    mop.size = instruction.d.size
    return mop


def _empty_mop(*, size: int | None = None):
    mop = ida_hexrays.mop_t()
    mop.erase()
    if size is not None:
        mop.size = size
    return mop


def _r6_nested_operand(mba, opcode: int):
    segment = _raw_register(R6_SEGMENT_REGISTER, size=R6_SEGMENT_SIZE)
    segment.valnum = R6_SEGMENT_VALNUM
    segment.oprops = 0
    address = ida_hexrays.mop_t()
    address.make_stkvar(mba, R6_STACK_OFFSET)
    address.size = R6_STACK_SIZE
    address.valnum = R6_STACK_VALNUM
    address.oprops = 0

    instruction = ida_hexrays.minsn_t(R6_LOAD_EA)
    instruction.opcode = opcode
    instruction.iprops = 0
    instruction.l = segment
    instruction.r = address
    instruction.d = _empty_mop(size=WIDTH_BYTES)
    operand = _instruction_mop(instruction)
    operand.size = WIDTH_BYTES
    operand.valnum = 0
    operand.oprops = 0
    return operand


def _r6_widened_boolean_carrier(mba, *, nested_opcode: int):
    comparison = ida_hexrays.minsn_t(R6_COMPARISON_EA)
    comparison.opcode = ida_hexrays.m_setnz
    comparison.iprops = 0
    comparison.l = _r6_nested_operand(mba, nested_opcode)
    comparison.r = _raw_number(0, size=WIDTH_BYTES)
    comparison.r.valnum = 0
    comparison.r.oprops = 0
    comparison.d = _empty_mop(size=1)
    comparison_operand = _instruction_mop(comparison)
    comparison_operand.size = 1
    comparison_operand.valnum = 0
    comparison_operand.oprops = 0

    widened = ida_hexrays.minsn_t(R6_XDU_EA)
    widened.opcode = ida_hexrays.m_xdu
    widened.iprops = 0
    widened.l = comparison_operand
    widened.r = _empty_mop()
    widened.d = _empty_mop(size=WIDTH_BYTES)
    widened_operand = _instruction_mop(widened)
    widened_operand.size = WIDTH_BYTES
    widened_operand.valnum = 0
    widened_operand.oprops = 0

    carrier = ast_dispatcher.AstLeaf("r6_widened_boolean")
    carrier.mop = MopSnapshot.from_mop(widened_operand)
    carrier.dest_size = WIDTH_BYTES
    carrier.proof_origin = ("r6-widened-boolean", nested_opcode)
    return carrier


def _full_identity(instruction):
    return raw_mop_identity(_instruction_mop(instruction))


def _freeze_pod(value):
    if isinstance(value, dict):
        return tuple(sorted((key, _freeze_pod(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_pod(item) for item in value)
    return value


def _walk_ast(source, path=()):
    yield path, source
    if source.is_node():
        if source.left is not None:
            yield from _walk_ast(source.left, path + (0,))
        if source.right is not None:
            yield from _walk_ast(source.right, path + (1,))


def _nodes_with_opcode(source, opcode):
    return [
        node
        for _, node in _walk_ast(source)
        if node.is_node() and node.opcode == opcode
    ]


def _snapshot_payload(node):
    assert isinstance(node.mop, MopSnapshot)
    return raw_mop_identity(node.mop.to_mop())


def _snapshot_backed_xdu_payload(source):
    widened_nodes = _nodes_with_opcode(source, ida_hexrays.m_xdu)
    assert len(widened_nodes) == 1
    widened = widened_nodes[0]
    assert isinstance(widened.mop, MopSnapshot)
    payload = _snapshot_payload(widened)
    assert payload["type"] == ida_hexrays.mop_d
    assert payload["instruction"]["opcode"] == ida_hexrays.m_xdu
    return payload


def _owned_mop_payload(mop):
    if isinstance(mop, MopSnapshot):
        return raw_mop_identity(mop.to_mop())
    if isinstance(mop, ida_hexrays.mop_t):
        owned = ida_hexrays.mop_t()
        owned.assign(mop)
        return raw_mop_identity(owned)
    return None


def _constant_payloads(source, value):
    return [
        _owned_mop_payload(node.mop)
        for _, node in _walk_ast(source)
        if not node.is_node() and node.is_constant() and node.value == value
    ]


def _widened_payload(source):
    widened = _nodes_with_opcode(source, ida_hexrays.m_xdu)[0]
    comparison = widened.left
    assert widened.dest_size == WIDTH_BYTES
    assert widened.right is None
    assert comparison.opcode == ida_hexrays.m_setnz
    assert comparison.dest_size == 1
    assert comparison.left.mop.t == ida_hexrays.mop_r
    assert comparison.left.mop.size == WIDTH_BYTES
    assert comparison.right.mop.t == ida_hexrays.mop_n
    assert comparison.right.mop.size == WIDTH_BYTES
    assert comparison.right.value == 0

    payload = _snapshot_backed_xdu_payload(source)
    assert payload["type"] == ida_hexrays.mop_d
    assert payload["size"] == WIDTH_BYTES
    widened_instruction = payload["instruction"]
    assert widened_instruction["opcode"] == ida_hexrays.m_xdu
    assert widened_instruction["d"]["size"] == WIDTH_BYTES
    comparison_operand = widened_instruction["l"]
    assert comparison_operand["type"] == ida_hexrays.mop_d
    assert comparison_operand["size"] == 1
    comparison_instruction = comparison_operand["instruction"]
    assert comparison_instruction["opcode"] == ida_hexrays.m_setnz
    assert comparison_instruction["d"]["size"] == 1
    assert comparison_instruction["l"]["type"] == ida_hexrays.mop_r
    assert comparison_instruction["l"]["size"] == WIDTH_BYTES
    assert comparison_instruction["r"]["type"] == ida_hexrays.mop_n
    assert comparison_instruction["r"]["size"] == WIDTH_BYTES
    assert comparison_instruction["r"]["value"] == 0
    return payload


def _r6_load_backed_widened_payload(source):
    widened_nodes = _nodes_with_opcode(source, ida_hexrays.m_xdu)
    assert len(widened_nodes) == 1
    widened = widened_nodes[0]
    comparison = widened.left
    assert widened.dest_size == WIDTH_BYTES
    assert widened.right is None
    assert comparison.opcode == ida_hexrays.m_setnz
    assert comparison.dest_size == 1
    assert comparison.left.is_leaf()
    assert not comparison.left.is_constant()
    assert comparison.left.mop.t == ida_hexrays.mop_d
    assert comparison.left.mop.size == WIDTH_BYTES
    assert comparison.right.mop.t == ida_hexrays.mop_n
    assert comparison.right.mop.size == WIDTH_BYTES
    assert comparison.right.value == 0

    payload = _snapshot_backed_xdu_payload(source)
    widened_instruction = payload["instruction"]
    comparison_operand = widened_instruction["l"]
    comparison_instruction = comparison_operand["instruction"]
    load_operand = comparison_instruction["l"]
    load_instruction = load_operand["instruction"]
    assert payload["oprops"] == 0
    assert payload["size"] == WIDTH_BYTES
    assert widened_instruction["ea"] == R6_XDU_EA
    assert widened_instruction["iprops"] == 0
    assert widened_instruction["d"]["type"] == ida_hexrays.mop_z
    assert widened_instruction["d"]["size"] == WIDTH_BYTES
    assert comparison_operand["oprops"] == 0
    assert comparison_operand["size"] == 1
    assert comparison_instruction["ea"] == R6_COMPARISON_EA
    assert comparison_instruction["iprops"] == 0
    assert comparison_instruction["d"]["type"] == ida_hexrays.mop_z
    assert comparison_instruction["d"]["size"] == 1
    assert load_operand["type"] == ida_hexrays.mop_d
    assert load_operand["oprops"] == 0
    assert load_operand["size"] == WIDTH_BYTES
    assert load_instruction["opcode"] == ida_hexrays.m_ldx
    assert load_instruction["ea"] == R6_LOAD_EA
    assert load_instruction["iprops"] == 0
    assert load_instruction["l"] == {
        "type": ida_hexrays.mop_r,
        "size": R6_SEGMENT_SIZE,
        "valnum": R6_SEGMENT_VALNUM,
        "oprops": 0,
        "register": R6_SEGMENT_REGISTER,
    }
    assert load_instruction["r"] == {
        "type": ida_hexrays.mop_S,
        "size": R6_STACK_SIZE,
        "valnum": R6_STACK_VALNUM,
        "oprops": 0,
        "stack_offset": R6_STACK_OFFSET,
    }
    assert load_instruction["d"]["type"] == ida_hexrays.mop_z
    assert load_instruction["d"]["size"] == WIDTH_BYTES
    return payload, load_operand


def _raw_nested_payloads(instruction, opcode):
    payloads = []

    def visit_operand(operand):
        if operand is None or operand.t != ida_hexrays.mop_d:
            return
        if operand.d.opcode == opcode:
            payloads.append(raw_mop_identity(operand))
        for child in (operand.d.l, operand.d.r, operand.d.d):
            visit_operand(child)

    for operand in (instruction.l, instruction.r, instruction.d):
        visit_operand(operand)
    return payloads


def _source_state(source):
    destination_payload = _owned_mop_payload(source.dst_mop)
    return (
        repr(source),
        source.ea,
        source.dest_size,
        tuple(
            (
                path,
                node.opcode if node.is_node() else None,
                node.dest_size,
                _freeze_pod(_owned_mop_payload(node.mop)),
                _freeze_pod(getattr(node, "proof_origin", None)),
            )
            for path, node in _walk_ast(source)
        ),
        _freeze_pod(destination_payload),
    )


def _nonregister_comparison_widened_boolean():
    comparison = _node(
        ida_hexrays.m_setnz,
        _constant(1),
        _constant(0),
        size=1,
    )
    return _node(ida_hexrays.m_xdu, comparison)


def _authorize_test_catalogue(adapter, *, monkeypatch, tmp_path) -> None:
    """Use the production certificate verifier to authorize this test catalogue."""

    monkeypatch.setenv("D810_CANONICAL_MATCH_FALLBACK", "1")
    monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
    snapshot, _ = attach_selected_certified_catalogue_snapshot((adapter,))
    runtime_mode = get_engine_info()["backend"]
    corpus_digest = hashlib.sha256(b"widened-boolean-test-corpus").hexdigest()
    toolchain_digest = hashlib.sha256(
        f"ida-9.4-{runtime_mode}".encode("ascii")
    ).hexdigest()
    payload = make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ShadowMatcherParityLedger(
            observation_count=1,
            legacy_match_count=1,
        ),
        runtime_mode=runtime_mode,
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
    )
    certificate_path = tmp_path / f"{adapter.name}.certificate.json"
    certificate_path.write_text(json.dumps(payload), encoding="utf-8")
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
        legacy_observation_count=1,
        observation_count=1,
    )
    attach_selected_certified_catalogue_snapshot(
        (adapter,),
        parity_certificate_path=certificate_path,
        parity_expectation=expectation,
        runtime_mode=runtime_mode,
    )
    assert adapter._structural_parity_authorized is True
    assert adapter.canonical_fallback_enabled is True


@pytest.fixture(scope="class")
def r6_live_mba(libobfuscated_setup):
    """Keep one live MBA owner for the native stack reference under test."""

    function_ea = get_func_ea("test_function_ollvm_fla_bcf_sub")
    assert function_ea != idaapi.BADADDR
    mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_CALLS)
    assert mba is not None
    return mba


@pytest.mark.usefixtures("ida_database")
class TestWidenedBooleanIsland:
    binary_name = "libobfuscated.dll"

    @pytest.mark.parametrize("kind", ("bnot-xor", "bnot-factor"))
    def test_native_clone_is_equivalent_and_full_payload_identity_is_stable(
        self, kind
    ) -> None:
        instruction, source = _materialize(_witness_ast(kind, predicate_register=56))
        clone_instruction = ida_hexrays.minsn_t(instruction)
        clone = minsn_to_ast(clone_instruction)
        assert clone is not None

        source_payload = _widened_payload(source)
        clone_payloads = _raw_nested_payloads(clone_instruction, ida_hexrays.m_xdu)
        assert clone_payloads == [source_payload]
        assert source_payload["instruction"]["ea"] == WITNESS_EA
        widened = _nodes_with_opcode(source, ida_hexrays.m_xdu)[0]
        widened_lowering = lower_hexrays_island(
            widened,
            destination_size=WIDTH_BYTES,
        )
        assert widened_lowering.term is not None
        assert widened_lowering.term.operation is None
        assert widened_lowering.term.leaf_key is not None
        assert widened_lowering.term.leaf_key not in widened_lowering.leafs
        assert (
            rebuild_hexrays_island(
                widened_lowering.term,
                lowering=widened_lowering,
                destination_size=WIDTH_BYTES,
            )
            is None
        )
        assert prove_native_ast_equivalence(source, clone, width=WIDTH_BITS)

    def test_ordinary_arithmetic_skips_widened_payload_inspection(
        self, monkeypatch
    ) -> None:
        _, source = _materialize(
            _node(
                ida_hexrays.m_or,
                _leaf("ordinary", 56),
                _constant(WITNESS_KEY),
            )
        )

        def unexpected_payload_inspection(*_args, **_kwargs):
            raise AssertionError("ordinary nodes must not inspect widened payloads")

        monkeypatch.setattr(
            island_backend,
            "_exact_widened_boolean_leaf_key",
            unexpected_payload_inspection,
        )
        lowering = lower_hexrays_island(source, destination_size=WIDTH_BYTES)

        assert lowering.term is not None

    @pytest.mark.parametrize(
        ("kind", "rule_class"),
        (
            ("bnot-xor", BnotXor_FactorRule_1),
            ("bnot-factor", Bnot_FactorRule_5),
        ),
    )
    def test_actual_rule_observes_emits_and_proves_without_mutating_source(
        self, kind, rule_class, monkeypatch, tmp_path
    ) -> None:
        instruction, source = _materialize(_witness_ast(kind, predicate_register=56))
        source_identity = _full_identity(instruction)
        source_widened_payload = _widened_payload(source)
        source_state = _source_state(source)
        adapter = IDAPatternAdapter(rule_class())
        _authorize_test_catalogue(
            adapter,
            monkeypatch=monkeypatch,
            tmp_path=tmp_path,
        )
        adapter._attempt_destination_size = WIDTH_BYTES
        provenance = adapter._catalogue_provenance()
        template = adapter.REPLACEMENT_PATTERN
        template_state = _source_state(template)
        assert all(leaf.mop is None for leaf in template.get_leaf_list())

        report = adapter.observe_structural_match(source)
        assert report is not None
        assert report.bindings is not None
        replacement = adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
            comparison_budget=64,
        )

        assert replacement is not None
        assert adapter._shadow_native_equivalence_verdict is True
        emitted_widened_payloads = _raw_nested_payloads(replacement, ida_hexrays.m_xdu)
        assert emitted_widened_payloads == [source_widened_payload]
        assert _full_identity(instruction) == source_identity
        assert _source_state(source) == source_state
        assert adapter._catalogue_provenance() == provenance
        assert _source_state(template) == template_state

    @pytest.mark.parametrize(
        ("kind", "rule_class"),
        (
            ("bnot-xor", BnotXor_FactorRule_1),
            ("bnot-factor", Bnot_FactorRule_5),
        ),
    )
    def test_actual_rule_live_path_accepts_ordinary_register_control(
        self, kind, rule_class, monkeypatch, tmp_path
    ) -> None:
        instruction, source = _materialize(
            _witness_ast(
                kind,
                predicate_register=56,
                predicate=_leaf("ordinary", 56),
            )
        )
        source_identity = _full_identity(instruction)
        source_state = _source_state(source)
        adapter = IDAPatternAdapter(rule_class())
        _authorize_test_catalogue(
            adapter,
            monkeypatch=monkeypatch,
            tmp_path=tmp_path,
        )
        adapter._attempt_destination_size = WIDTH_BYTES
        provenance = adapter._catalogue_provenance()
        template = adapter.REPLACEMENT_PATTERN
        template_state = _source_state(template)

        report = adapter.observe_structural_match(source)
        assert report is not None
        assert report.bindings is not None
        replacement = adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
            comparison_budget=64,
        )

        assert replacement is not None
        assert adapter._shadow_native_equivalence_verdict is True
        assert _full_identity(instruction) == source_identity
        assert _source_state(source) == source_state
        assert adapter._catalogue_provenance() == provenance
        assert _source_state(template) == template_state

    @pytest.mark.parametrize(
        ("kind", "rule_class", "widened_path"),
        (
            ("bnot-xor", BnotXor_FactorRule_1, (1, 0)),
            ("bnot-factor", Bnot_FactorRule_5, (0, 0, 0)),
        ),
        ids=("bnot-xor-load", "bnot-factor-load"),
    )
    def test_actual_rule_accepts_r6_load_backed_widened_boolean(
        self,
        kind,
        rule_class,
        widened_path,
        r6_live_mba,
        monkeypatch,
        tmp_path,
    ) -> None:
        instruction, source = _materialize(
            _witness_ast(
                kind,
                predicate_register=56,
                predicate=_r6_widened_boolean_carrier(
                    r6_live_mba,
                    nested_opcode=ida_hexrays.m_ldx,
                ),
            )
        )
        source_nodes = dict(_walk_ast(source))
        assert source_nodes[widened_path].opcode == ida_hexrays.m_xdu
        source_identity = _full_identity(instruction)
        source_widened_payload, source_load_payload = _r6_load_backed_widened_payload(
            source
        )
        source_state = _source_state(source)
        adapter = IDAPatternAdapter(rule_class())
        _authorize_test_catalogue(
            adapter,
            monkeypatch=monkeypatch,
            tmp_path=tmp_path,
        )
        adapter._attempt_destination_size = WIDTH_BYTES
        provenance = adapter._catalogue_provenance()
        template = adapter.REPLACEMENT_PATTERN
        template_state = _source_state(template)

        report = adapter.observe_structural_match(source)
        assert report is not None
        assert report.bindings is not None
        replacement = adapter.match_structural_and_replace(
            source,
            bucket_size=1,
            attempted_rule_count=1,
            comparison_budget=64,
        )

        assert replacement is not None
        assert adapter._shadow_native_equivalence_verdict is True
        assert _raw_nested_payloads(replacement, ida_hexrays.m_xdu) == [
            source_widened_payload
        ]
        assert _raw_nested_payloads(replacement, ida_hexrays.m_ldx) == [
            source_load_payload
        ]
        replacement_ast = minsn_to_ast(replacement)
        assert replacement_ast is not None
        assert prove_native_ast_equivalence(
            source,
            replacement_ast,
            width=WIDTH_BITS,
        )
        assert _full_identity(instruction) == source_identity
        assert _source_state(source) == source_state
        assert adapter._catalogue_provenance() == provenance
        assert _source_state(template) == template_state

    def test_r6_widened_boolean_refuses_nested_call_mop_d(self, r6_live_mba) -> None:
        instruction, source = _materialize(
            _node(
                ida_hexrays.m_or,
                _r6_widened_boolean_carrier(
                    r6_live_mba,
                    nested_opcode=ida_hexrays.m_call,
                ),
                _constant(WITNESS_KEY),
            )
        )
        source_identity = _full_identity(instruction)
        widened = _nodes_with_opcode(source, ida_hexrays.m_xdu)[0]
        comparison = widened.left
        assert comparison.left.is_leaf()
        assert not comparison.left.is_constant()
        assert comparison.left.dest_size == WIDTH_BYTES
        assert comparison.left.mop.size == WIDTH_BYTES
        widened_payload = _snapshot_backed_xdu_payload(source)
        comparison_payload = _snapshot_payload(comparison)
        nested_payload = _snapshot_payload(comparison.left)
        assert widened_payload["instruction"]["l"] == comparison_payload
        assert comparison_payload["instruction"]["l"] == nested_payload
        assert nested_payload["type"] == ida_hexrays.mop_d
        assert nested_payload["size"] == WIDTH_BYTES
        assert nested_payload["instruction"]["opcode"] == ida_hexrays.m_call
        assert nested_payload["instruction"]["ea"] == R6_LOAD_EA
        assert nested_payload["instruction"]["iprops"] == 0

        lowering = lower_hexrays_island(source, destination_size=WIDTH_BYTES)

        assert lowering.term is None
        assert not prove_native_ast_equivalence(
            source,
            source.clone(),
            width=WIDTH_BITS,
        )
        assert _full_identity(instruction) == source_identity

    @pytest.mark.parametrize(
        ("changed_register", "changed_key"),
        ((64, WITNESS_KEY), (56, WITNESS_KEY ^ 1)),
    )
    def test_changed_native_payload_is_distinct_and_not_equivalent(
        self, changed_register, changed_key
    ) -> None:
        original_instruction, original = _materialize(
            _witness_ast("bnot-xor", predicate_register=56)
        )
        changed_instruction, changed = _materialize(
            _witness_ast(
                "bnot-xor",
                predicate_register=changed_register,
                key=changed_key,
            )
        )

        original_payload = _widened_payload(original)
        changed_payload = _widened_payload(changed)
        original_keys = _constant_payloads(original, WITNESS_KEY)
        changed_keys = _constant_payloads(changed, changed_key)
        assert len(original_keys) == len(changed_keys) == 2
        assert prove_native_ast_equivalence(
            original, original.clone(), width=WIDTH_BITS
        )
        assert _full_identity(original_instruction) != _full_identity(
            changed_instruction
        )
        if changed_register != 56:
            assert changed_payload != original_payload
            assert changed_keys == original_keys
        else:
            assert changed_payload == original_payload
            assert changed_keys != original_keys
        assert not prove_native_ast_equivalence(original, changed, width=WIDTH_BITS)

    @pytest.mark.parametrize("mode", ("register", "unknown-width"))
    def test_ast_and_owned_snapshot_geometry_must_agree(self, mode) -> None:
        _, source = _materialize(_witness_ast("bnot-xor", predicate_register=56))
        source_state = _source_state(source)
        original_payload = _widened_payload(source)
        changed = source.clone()
        widened = _nodes_with_opcode(changed, ida_hexrays.m_xdu)[0]
        assert _snapshot_payload(widened) == original_payload

        # The mutable clone now exposes another input register while its owned
        # xdu payload still contains the original register.  Neither
        # representation may override the disagreement.
        if mode == "register":
            widened.left.left.mop = MopSnapshot(
                t=ida_hexrays.mop_r,
                size=WIDTH_BYTES,
                reg=64,
            )
            assert widened.left.left.mop.reg == 64
        else:
            widened.dest_size = None
            assert widened.dest_size is None
        assert _snapshot_payload(widened) == original_payload
        assert not prove_native_ast_equivalence(
            changed,
            changed.clone(),
            width=WIDTH_BITS,
        )
        assert _source_state(source) == source_state

    @pytest.mark.parametrize(
        "near_miss",
        (
            lambda: _widened_boolean(56, comparison_value=1),
            lambda: _widened_boolean(
                56,
                comparison_opcode=ida_hexrays.m_setz,
            ),
            lambda: _widened_boolean(56, comparison_result_size=2),
            lambda: _widened_boolean(56, register_size=8),
            _nonregister_comparison_widened_boolean,
            lambda: _node(ida_hexrays.m_xdu, _leaf("direct", 56)),
            lambda: _node(
                ida_hexrays.m_xdu,
                _node(
                    ida_hexrays.m_setnz,
                    _leaf("mixed", 56, size=4),
                    _constant(0, size=2),
                    size=1,
                ),
            ),
            lambda: _widened_boolean(56, extension_size=8),
        ),
        ids=(
            "nonzero-comparison-rhs",
            "setz-comparison",
            "wrong-set-result-width",
            "wrong-register-width",
            "nonregister-comparison-lhs",
            "direct-xdu-register",
            "mixed-width",
            "wider-xdu",
        ),
    )
    def test_snapshot_backed_xdu_near_misses_remain_refused(self, near_miss) -> None:
        instruction, source = _materialize(
            _node(ida_hexrays.m_or, near_miss(), _constant(WITNESS_KEY))
        )
        source_identity = _full_identity(instruction)
        near_miss_payload = _snapshot_backed_xdu_payload(source)
        _, exact_source = _materialize(
            _node(
                ida_hexrays.m_or,
                _widened_boolean(56),
                _constant(WITNESS_KEY),
            )
        )
        assert near_miss_payload != _widened_payload(exact_source)

        assert not prove_native_ast_equivalence(
            source, source.clone(), width=WIDTH_BITS
        )
        assert _full_identity(instruction) == source_identity

    @pytest.mark.parametrize(
        "unsupported",
        (
            lambda: _node(ida_hexrays.m_call, _leaf("call", 56)),
            lambda: _node(
                ida_hexrays.m_ldx, _leaf("segment", 56), _leaf("address", 64)
            ),
            lambda: _node(ida_hexrays.m_stx, _leaf("value", 56), _leaf("address", 64)),
            lambda: _node(
                ida_hexrays.m_udiv, _leaf("dividend", 56), _leaf("divisor", 64)
            ),
        ),
        ids=(
            "call",
            "load",
            "store",
            "udiv",
        ),
    )
    def test_general_unsupported_opcodes_remain_refused(self, unsupported) -> None:
        source = unsupported()
        source.ea = WITNESS_EA
        assert source.mop is None

        assert not prove_native_ast_equivalence(
            source, source.clone(), width=WIDTH_BITS
        )
