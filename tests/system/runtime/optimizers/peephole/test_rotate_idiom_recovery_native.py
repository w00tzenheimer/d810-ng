"""Native Hex-Rays construction checks for rotate-idiom recovery.

The structural matcher is deliberately tested without IDA.  This test covers
the boundary that cannot be faked: Hex-Rays must accept the value-producing
``__ROL8__`` helper form returned by ``mba_t.create_helper_call``.
"""

from __future__ import annotations

import pytest

import ida_hexrays
import idautils
import idaapi
import idc

from d810.core import MOP_TO_AST_CACHE
from d810.hexrays.mutation import deferred_modifier as dm
from d810.hexrays.mutation.block_instruction_commit import (
    HexRaysBlockInstructionCommitter,
)
from d810.hexrays.mutation.instruction_commit import NativeEpoch
from d810.hexrays.utils.hexrays_helpers import dup_mop
from d810.hexrays.utils.hexrays_formatters import format_minsn_t
from d810.backends.mba.hexrays_island import (
    lower_hexrays_island,
    rebuild_hexrays_island,
)
from d810.backends.mba.native_rotate_helper import (
    make_rotate_helper_call,
    materialize_rotate_term,
)
from d810.hexrays.expr import ast as ast_dispatcher
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from tests.system.runtime.conftest import gen_microcode_at_maturity
from tests.system.runtime.mutation_gateway import make_mutation_gateway


def _find_64_bit_value_and_destination(mba):
    for block_serial in range(mba.qty):
        block = mba.get_mblock(block_serial)
        if block is None:
            continue
        instruction = block.head
        while instruction is not None:
            if (
                instruction.l is not None
                and instruction.d is not None
                and instruction.l.size == 8
                and instruction.d.size == 8
                and instruction.d.t != ida_hexrays.mop_z
            ):
                return block, instruction, dup_mop(instruction.l), dup_mop(instruction.d)
            instruction = instruction.next
    pytest.fail("the fixture database did not expose a usable 64-bit microcode value")


def _find_fixture_mba_with_64_bit_value():
    for function_ea in idautils.Functions():
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        if mba is None:
            continue
        try:
            return mba, _find_64_bit_value_and_destination(mba)
        except pytest.fail.Exception:
            continue
    pytest.fail("fixture database has no usable 64-bit microcode value")


def _walk_ast(node):
    """Yield the dispatcher AST nodes below a live minsn_to_ast result."""

    if node is None:
        return
    yield node
    for attribute in ("left", "right", "dst"):
        child = getattr(node, attribute, None)
        if child is not None:
            yield from _walk_ast(child)


def _helper_call_args(call):
    """Read the live create_helper_call argument layout without guessing."""

    for container in (call.r, call.d):
        if container is not None and container.t == ida_hexrays.mop_f:
            assert container.f is not None
            return tuple(container.f.args)
    if call.r is not None and call.d is not None:
        if call.r.t != ida_hexrays.mop_z and call.d.t != ida_hexrays.mop_z:
            return (call.r, call.d)
    return ()


def _fresh_register_operand(block, size):
    register = block.mba.alloc_kreg(size, True)
    assert register != ida_hexrays.mr_none
    operand = ida_hexrays.mop_t()
    operand.make_reg(register, size)
    return operand


class TestRotateIdiomRecoveryNative:
    binary_name = "libobfuscated.dll"

    def test_make_rol8_helper_call_uses_native_value_producing_form(self, libobfuscated_setup):
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery_native import (
            make_rol8_helper_call,
        )

        mba, (block, instruction, base, output) = _find_fixture_mba_with_64_bit_value()

        replacement = make_rol8_helper_call(
            block,
            ea=instruction.ea,
            base=base,
            rotation=31,
            output=output,
        )

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.d.size == 8
        assert replacement.l.t == ida_hexrays.mop_d
        call = replacement.l.d
        assert call.opcode == ida_hexrays.m_call
        assert call.l.t == ida_hexrays.mop_h
        assert call.l.helper == "__ROL8__"
        rendered = format_minsn_t(replacement)
        assert "call !__ROL8__" in rendered
        assert "#0x1F.1" in rendered
        instruction.swap(replacement)
        block.mark_lists_dirty()
        mba.verify(True)

    def test_make_rol8_wrapper_preserves_legacy_integer_coercion(
        self, libobfuscated_setup
    ):
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery_native import (
            make_rol8_helper_call,
        )

        mba, (block, instruction, base, output) = _find_fixture_mba_with_64_bit_value()
        replacement = make_rol8_helper_call(
            block,
            ea=instruction.ea,
            base=base,
            rotation=31.9,
            output=output,
        )

        assert replacement is not None
        assert replacement.l.d.l.helper == "__ROL8__"
        native_args = _helper_call_args(replacement.l.d)
        assert len(native_args) == 2
        assert native_args[1].nnn.value == 31

    def test_shared_helper_builder_accepts_exact_width_helper_and_zero_count(
        self, libobfuscated_setup
    ):
        mba, (block, instruction, base, output) = _find_fixture_mba_with_64_bit_value()

        replacement = make_rotate_helper_call(
            block,
            ea=instruction.ea,
            helper="__ROR8__",
            base=base,
            rotation=0,
            output=output,
        )

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.l.d.l.helper == "__ROR8__"
        native_args = _helper_call_args(replacement.l.d)
        assert len(native_args) == 2
        assert native_args[0].size == 8
        assert native_args[1].size == 1
        assert native_args[1].nnn.value == 0
        instruction.swap(replacement)
        block.mark_lists_dirty()
        mba.verify(True)

    def test_materialize_rotate_term_uses_active_block_and_destination(
        self, libobfuscated_setup
    ):
        mba, (block, instruction, base, output) = _find_fixture_mba_with_64_bit_value()
        leaf = ast_dispatcher.AstLeaf("x")
        leaf.mop = MopSnapshot.from_mop(base)
        leaf.dest_size = 8
        source = ast_dispatcher.AstNode(ida_hexrays.m_call, leaf, None)
        source.right = ast_dispatcher.AstConstant("7", 7, 1)
        source.right.mop = MopSnapshot(t=ida_hexrays.mop_n, size=1, value=7)
        source.right.dest_size = 1
        source.func_name = "__ROR8__"
        source.dest_size = 8

        lowering = lower_hexrays_island(source, destination_size=8)

        assert lowering.term is not None
        assert lowering.term.operation == "ror"
        assert lowering.term.width == 64
        assert lowering.term.shift_count == 7
        assert len(lowering.term.children) == 1
        replacement = materialize_rotate_term(
            lowering.term,
            lowering=lowering,
            block=block,
            destination=output,
        )

        assert replacement is not None
        assert replacement.opcode == ida_hexrays.m_mov
        assert replacement.l.d.l.helper == "__ROR8__"
        instruction.swap(replacement)
        block.mark_lists_dirty()
        mba.verify(True)

    @pytest.mark.parametrize("parent_opcode", [ida_hexrays.m_add, ida_hexrays.m_shl])
    def test_rebuild_rejects_nested_instruction_level_rotate(
        self, libobfuscated_setup, parent_opcode
    ):
        """A minsn helper result cannot be embedded in a parent AstNode."""

        mba, (block, instruction, base, output) = _find_fixture_mba_with_64_bit_value()
        rotate_leaf = ast_dispatcher.AstLeaf("x")
        rotate_leaf.mop = MopSnapshot.from_mop(base)
        rotate_leaf.dest_size = 8
        rotate = ast_dispatcher.AstNode(ida_hexrays.m_call, rotate_leaf, None)
        rotate.right = ast_dispatcher.AstConstant("7", 7, 1)
        rotate.right.mop = MopSnapshot(t=ida_hexrays.mop_n, size=1, value=7)
        rotate.right.dest_size = 1
        rotate.func_name = "__ROL8__"
        rotate.dest_size = 8

        if parent_opcode == ida_hexrays.m_add:
            sibling = ast_dispatcher.AstLeaf("y")
            sibling.mop = MopSnapshot.from_mop(base)
            sibling.dest_size = 8
        else:
            sibling = ast_dispatcher.AstConstant("1", 1, 1)
            sibling.mop = MopSnapshot(t=ida_hexrays.mop_n, size=1, value=1)
            sibling.dest_size = 1
        parent = ast_dispatcher.AstNode(parent_opcode, rotate, sibling)
        parent.dest_size = 8

        lowering = lower_hexrays_island(parent, destination_size=8)
        assert lowering.term is not None
        assert lowering.term.operation == (
            "add" if parent_opcode == ida_hexrays.m_add else "shl"
        )
        assert any(child.operation == "rol" for child in lowering.term.children)

        rebuilt = rebuild_hexrays_island(
            lowering.term,
            lowering=lowering,
            destination_size=8,
            block=block,
            destination=output,
        )

        assert rebuilt is None

    def test_cython_cache_keeps_sequential_same_shape_rol_and_ror_distinct(
        self, libobfuscated_setup
    ):
        """Identical operands must not reuse a prior opposite-direction AST."""

        mba, (block, instruction, _, _) = _find_fixture_mba_with_64_bit_value()
        base = _fresh_register_operand(block, 8)
        output = _fresh_register_operand(block, 8)
        rol = make_rotate_helper_call(
            block,
            ea=instruction.ea,
            helper="__ROL8__",
            base=base,
            rotation=7,
            output=output,
        )
        ror = make_rotate_helper_call(
            block,
            ea=instruction.ea,
            helper="__ROR8__",
            base=base,
            rotation=7,
            output=output,
        )
        assert rol is not None
        assert ror is not None

        def helper_name(instruction):
            ast = minsn_to_ast(instruction)
            assert ast is not None
            names = [
                node.func_name
                for node in _walk_ast(ast)
                if getattr(node, "opcode", None) == ida_hexrays.m_call
            ]
            assert len(names) == 1
            return names[0]

        MOP_TO_AST_CACHE.clear()
        try:
            assert helper_name(rol) == "__ROL8__"
            assert helper_name(ror) == "__ROR8__"
        finally:
            MOP_TO_AST_CACHE.clear()

    @pytest.mark.parametrize(
        ("helper", "size", "count"),
        [
            ("__ROL1__", 1, 3),
            ("__ROL2__", 2, 7),
            ("__ROL4__", 4, 13),
            ("__ROL8__", 8, 31),
            ("__ROR1__", 1, 5),
            ("__ROR2__", 2, 9),
            ("__ROR4__", 4, 17),
            ("__ROR8__", 8, 47),
        ],
    )
    def test_live_helper_ast_round_trip_through_lower_and_rebuild(
        self, libobfuscated_setup, helper, size, count
    ):
        """Exercise the actual create_helper_call -> minsn_to_ast boundary."""

        mba, (block, instruction, _, _) = _find_fixture_mba_with_64_bit_value()
        base = _fresh_register_operand(block, size)
        output = _fresh_register_operand(block, size)
        call = make_rotate_helper_call(
            block,
            ea=instruction.ea,
            helper=helper,
            base=base,
            rotation=count,
            output=output,
        )
        assert call is not None
        assert call.opcode == ida_hexrays.m_mov
        assert call.l.t == ida_hexrays.mop_d
        assert call.l.d.opcode == ida_hexrays.m_call
        assert call.l.d.l.t == ida_hexrays.mop_h
        assert call.l.d.l.helper == helper
        native_args = _helper_call_args(call.l.d)
        assert len(native_args) == 2
        assert native_args[0].size == size
        assert native_args[1].size == 1
        assert native_args[1].nnn.value == count

        ast = minsn_to_ast(call)
        assert ast is not None
        helper_nodes = [
            node
            for node in _walk_ast(ast)
            if getattr(node, "opcode", None) == ida_hexrays.m_call
        ]
        assert len(helper_nodes) == 1
        helper_ast = helper_nodes[0]
        assert helper_ast.func_name == helper
        assert helper_ast.dest_size == size
        assert helper_ast.left is not None
        assert helper_ast.right is not None
        assert helper_ast.right.value == count
        assert helper_ast.right.size == 1
        assert helper_ast.right.dest_size == 1

        lowering = lower_hexrays_island(helper_ast, destination_size=size)
        assert lowering.term is not None
        assert lowering.term.operation == ("rol" if "ROL" in helper else "ror")
        assert lowering.term.width == size * 8
        assert lowering.term.shift_count == count
        assert len(lowering.term.children) == 1
        child = lowering.term.children[0]
        assert child.leaf_key in lowering.leafs
        source_node = lowering.leafs[child.leaf_key]
        source_mop = source_node.mop
        if isinstance(source_mop, MopSnapshot):
            source_mop = source_mop.to_mop()
        direct = make_rotate_helper_call(
            block,
            ea=instruction.ea,
            helper=helper,
            base=source_mop,
            rotation=count,
            output=output,
        )
        assert direct is not None

        rebuilt = rebuild_hexrays_island(
            lowering.term,
            lowering=lowering,
            destination_size=size,
            block=block,
            destination=output,
        )
        assert rebuilt is not None
        assert rebuilt.opcode == ida_hexrays.m_mov
        assert rebuilt.d.size == size
        assert rebuilt.l.d.opcode == ida_hexrays.m_call
        assert rebuilt.l.d.l.helper == helper
        rebuilt_args = _helper_call_args(rebuilt.l.d)
        assert len(rebuilt_args) == 2
        assert rebuilt_args[0].size == size
        assert rebuilt_args[1].size == 1
        assert rebuilt_args[1].nnn.value == count

    def test_native_rule_matches_both_masm_murmur_shapes(
        self,
        libobfuscated_setup,
        monkeypatch,
    ):
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery_native import (
            RotateIdiomRecoveryBlockRule,
            _expression_from_mop,
        )
        from d810.optimizers.microcode.instructions.peephole import (
            rotate_idiom_recovery_native as native,
        )
        from d810.optimizers.microcode.instructions.peephole.rotate_idiom_recovery import (
            match_rol64_idiom,
        )

        function_ea = idc.get_name_ea_simple("Eid_ComputeTwoQwordBufferHash")
        assert function_ea != idaapi.BADADDR
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT2)
        assert mba is not None
        rule = RotateIdiomRecoveryBlockRule()
        candidates = []
        or_expressions = []

        def collect_or_expressions(mop):
            if mop is None or mop.t != ida_hexrays.mop_d or mop.d is None:
                return
            if mop.d.opcode == ida_hexrays.m_or:
                or_expressions.append(_expression_from_mop(mop))
            collect_or_expressions(mop.d.l)
            collect_or_expressions(mop.d.r)

        for block_serial in range(mba.qty):
            block = mba.get_mblock(block_serial)
            if block is None:
                continue
            instruction = block.head
            while instruction is not None:
                candidates.append(format_minsn_t(instruction))
                collect_or_expressions(instruction.l)
                collect_or_expressions(instruction.r)
                instruction = instruction.next

        assert len(or_expressions) == 2, "\n".join(candidates)
        assert all(match_rol64_idiom(expression) is not None for expression in or_expressions), or_expressions

        def unexpected_materialization(*_args, **_kwargs):
            pytest.fail("proposal must not allocate or build native helper calls")

        monkeypatch.setattr(
            native,
            "_fresh_kreg_output_from_context",
            unexpected_materialization,
        )
        monkeypatch.setattr(
            native,
            "_helper_call_from_detached_root",
            unexpected_materialization,
        )

        def render_mba():
            rendered = []
            for serial in range(mba.qty):
                block = mba.get_mblock(serial)
                if block is None:
                    continue
                instruction = block.head
                while instruction is not None:
                    rendered.append(format_minsn_t(instruction))
                    instruction = instruction.next
            return tuple(rendered)

        before_proposal = render_mba()
        proposals = []
        for block_serial in range(mba.qty):
            block = mba.get_mblock(block_serial)
            if block is None:
                continue
            candidate = rule.propose_instruction_batch(
                block,
                epoch=NativeEpoch.from_mba(mba),
            )
            if candidate is not None:
                proposals.append((block, candidate))

        assert proposals, "the native Murmur fixture did not expose a replaceable block"
        assert sum(
            len(getattr(edit.materializer, "roots", ()))
            for _block, candidate in proposals
            for edit in candidate.edits
        ) == 2
        assert all(
            len({edit.anchor for edit in candidate.edits}) == len(candidate.edits)
            for _block, candidate in proposals
        )
        assert render_mba() == before_proposal

        with pytest.raises(RuntimeError, match="optblock-owned commit"):
            rule.optimize(proposals[0][0])

        # The proposal is detached; the central committer owns all helper
        # construction, insertion, swap, dirty-list, and verification writes.
        monkeypatch.undo()
        for block, candidate in proposals:
            modifier = dm.DeferredGraphModifier(
                mba,
                mutation_gateway=make_mutation_gateway(mba),
            )
            committer = HexRaysBlockInstructionCommitter(
                epoch_provider=lambda _block, epoch=candidate.epoch_before: epoch,
            )
            receipt = committer.commit(
                block=block,
                candidate=candidate,
                modifier=modifier,
            )
            assert receipt.committed, receipt
            assert receipt.applied_edit_count == len(candidate.edits)
            assert receipt.epoch_after == candidate.epoch_before

        try:
            mba.verify(True)
        except RuntimeError as error:
            pytest.fail(f"MBA verification failed after hosted commit: {error}")

        rendered = render_mba()
        assert sum("call !__ROL8__" in line for line in rendered) == 2
        for block, _candidate in proposals:
            assert rule.propose_instruction_batch(
                block,
                epoch=NativeEpoch.from_mba(mba),
            ) is None

    def test_eid_profile_installs_rotate_rule(self, libobfuscated_setup, d810_state):
        with d810_state() as state:
            index = next(
                index
                for index, project in enumerate(state.project_manager.projects())
                if project.path.name == "eidolon_v3_const_solve.json"
            )
            state.load_project(index)
            assert "RotateIdiomRecoveryBlockRule" in {
                rule.name for rule in state.current_blk_rules
            }
            state.start_d810()
            function_ea = idc.get_name_ea_simple("Eid_ComputeTwoQwordBufferHash")
            report = state.manager.get_effective_execution_report(function_ea)
            rotate_decisions = [
                decision
                for decision in report.decisions
                if decision.stage_id == "rotate-idiom-recovery" and decision.active
            ]
            assert len(rotate_decisions) == 1, report
            assert rotate_decisions[0].ownership.value == "hexrays_hosted"
            assert rotate_decisions[0].host.value == "hexrays_optblock"
            assert rotate_decisions[0].scope.value == "block"

    def test_masm_fixture_renders_two_nested_rol8_calls(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
        pseudocode_to_string,
    ):
        """Prove the real hook, helper lowering, and ctree renderer together.

        The production Eid profile intentionally retains its much broader
        solver portfolio.  This fixture isolates the new value-only rule so a
        failure is attributable to rotate lowering rather than an unrelated
        solver rewrite in a synthetic MASM body.
        """

        with d810_state() as state:
            # IDA's SWIG binding creates a fresh ``mba_t`` proxy for each
            # ``block.mba`` access.  Hosted admission compares two epochs in
            # one callback, so use the stable native pointer identity for this
            # end-to-end fixture rather than the transient Python proxy id.
            original_epoch_from_mba = NativeEpoch.from_mba

            def stable_epoch_from_mba(cls, mba, **kwargs):
                epoch = original_epoch_from_mba.__func__(cls, mba, **kwargs)
                stable_identity = getattr(mba, "this", None)
                if stable_identity is None:
                    return epoch
                return type(epoch)(
                    function_ea=epoch.function_ea,
                    mba_identity=int(stable_identity),
                    maturity=epoch.maturity,
                    generation=epoch.generation,
                )

            monkeypatch.setattr(
                NativeEpoch,
                "from_mba",
                classmethod(stable_epoch_from_mba),
            )
            index = next(
                index
                for index, project in enumerate(state.project_manager.projects())
                if project.path.name == "eidolon_v3_const_solve.json"
            )
            state.load_project(index)
            state.current_ins_rules = []
            state.current_blk_rules = [
                rule
                for rule in state.current_blk_rules
                if rule.name == "RotateIdiomRecoveryBlockRule"
            ]
            assert len(state.current_blk_rules) == 1
            state.manager.configure_external_implementation_bindings({})
            # This test deliberately narrows the live rule collections to the
            # native block rule.  Keep the manager's compiled schedule in the
            # same isolated state so unrelated constant stages are not treated
            # as missing registrations during scope compilation.
            state.manager.configure_constant_simplification_schedule(None)
            state.start_d810()

            function_ea = idc.get_name_ea_simple("Eid_ComputeTwoQwordBufferHash")
            assert function_ea != idaapi.BADADDR
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None
            code = pseudocode_to_string(cfunc.get_pseudocode())

            assert code.count("__ROL8__") == 2, code
            assert len(
                state.manager.stats.cfg_rule_usages["RotateIdiomRecoveryBlockRule"]
            ) >= 1
