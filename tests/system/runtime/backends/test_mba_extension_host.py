from __future__ import annotations

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
from d810.mba.typed_term import TypedBvTerm  # noqa: E402


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


@pytest.mark.usefixtures("libobfuscated_setup")
class TestNativeMbaExtensionHost:
    binary_name = "libobfuscated.dll"

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

    def test_rebuild_rejects_ast_candidate_without_destination(self):
        host = native_mba_host_services()
        source = _node(ida_hexrays.m_xor, _leaf("x", 1), _constant(0))
        candidate = host.capture_ast(source, destination_size=4)
        assert candidate.raw_term is not None
        leaf = next(
            node for node in candidate.raw_term.children if node.leaf_key is not None
        )

        assert host.rebuild(candidate, leaf) is None

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
