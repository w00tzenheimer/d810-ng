# distutils: language = c++
# cython: language_level=3, embedsignature=True
# cython: cdivision=True
# distutils: define_macros=__EA64__=1
from __future__ import annotations
import abc
import dataclasses
import typing

import cython

import ida_hexrays
import idaapi

from d810._vendor import typing_extensions as _compat
from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.core import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
)
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    mop_tree,
    mop_type_to_string,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.hexrays_helpers import (
    AND_TABLE,
    MBA_RELATED_OPCODES,
    MINSN_TO_AST_FORBIDDEN_OPCODES,
    OPCODES_INFO,
    Z3_SPECIAL_OPERANDS,
    equal_mops_ignore_size,
    is_rotate_helper_call,
    structural_mop_hash,
)
from d810.speedups.expr.c_ast_evaluate import AstEvaluator
from d810.core import NOT_GIVEN

logger = getLogger(__name__)


# Pre-computed "N" signature lists for depth signatures.
# _N_SIGS[k] == ["N"] * (2 ** k) for k in 0..7 (covers depths up to 8).
cdef tuple _N_SIGS = tuple(["N"] * (2**k) for k in range(8))


cdef inline list _get_n_sig(int k):
    """Return cached ["N"] * (2**k) list, or compute if k >= 8."""
    if k < 8:
        return _N_SIGS[k]
    return ["N"] * (2**k)


def get_constant_mop(value: int, size: int) -> ida_hexrays.mop_t:
    """
    Returns a cached or new mop_t for a constant value.
    This avoids repeated calls to mop_t.__init__ and make_number.
    """
    key = (value, size)
    if key in MOP_CONSTANT_CACHE:
        return MOP_CONSTANT_CACHE[key]

    # Not in cache, create it once and store it.
    cst_mop = ida_hexrays.mop_t()
    cst_mop.make_number(value, size)
    MOP_CONSTANT_CACHE[key] = cst_mop
    return cst_mop

@dataclasses.dataclass(slots=True)
class AstInfo:
    ast: AstBase
    number_of_use: int

    def __str__(self):
        return f"{self.ast} used {self.number_of_use} times: {format_mop_t(self.ast.mop) if self.ast.mop else 0}"

cdef class AstBase:
    cdef public dict sub_ast_info_by_index
    cdef public object mop
    cdef public object dst_mop
    cdef public object dest_size
    cdef public object ea
    cdef public object ast_index
    # cdef public ida_hexrays.mop_t dst_mop
    # cdef public int dest_size
    # cdef public int ea
    # cdef public int ast_index

    @abc.abstractmethod
    def is_frozen(self) -> bool:
        raise NotImplementedError("AstBase.is_frozen must be overridden")

    @abc.abstractmethod
    def clone(self):
        raise NotImplementedError("AstBase.clone must be overridden")

    @abc.abstractmethod
    def freeze(self) -> None:
        raise NotImplementedError("AstBase.freeze must be overridden")

    @abc.abstractmethod
    def is_node(self) -> bool:
        raise NotImplementedError("AstBase.is_node must be overridden")

    @abc.abstractmethod
    def is_leaf(self) -> bool:
        raise NotImplementedError("AstBase.is_leaf must be overridden")

    @abc.abstractmethod
    def is_constant(self) -> bool:
        raise NotImplementedError("AstBase.is_constant must be overridden")

    @abc.abstractmethod
    def compute_sub_ast(self) -> None:
        raise NotImplementedError("AstBase.compute_sub_ast must be overridden")

    @abc.abstractmethod
    def get_leaf_list(self) -> list[AstLeaf]:
        raise NotImplementedError("AstBase.get_leaf_list must be overridden")

    @abc.abstractmethod
    def reset_mops(self) -> None:
        raise NotImplementedError("AstBase.reset_mops must be overridden")

    @abc.abstractmethod
    def _copy_mops_from_ast(self, other: AstBase, read_only: bool = False) -> bool:
        raise NotImplementedError("AstBase._copy_mops_from_ast must be overridden")

    @abc.abstractmethod
    def create_mop(self, ea: int) -> ida_hexrays.mop_t:
        raise NotImplementedError("AstBase.create_mop must be overridden")

    @abc.abstractmethod
    def get_pattern(self) -> str:
        raise NotImplementedError("AstBase.get_pattern must be overridden")

    @abc.abstractmethod
    def evaluate(self, dict_index_to_value: dict[int, int]) -> int:
        raise NotImplementedError("AstBase.evaluate must be overridden")

    @abc.abstractmethod
    def get_depth_signature(self, depth: int) -> list[str]:
        raise NotImplementedError("AstBase.get_depth_signature must be overridden")

    def __bool__(self) -> bool:
        return True


cdef class AstNode(AstBase):
    cdef public object opcode
    cdef public AstBase left
    cdef public AstBase right
    cdef public AstBase dst
    cdef public object dst_size
    cdef public object dst_mop
    cdef public list opcodes
    cdef public bint is_candidate_ok
    cdef public list leafs
    cdef public dict leafs_by_name
    cdef public object func_name
    cdef public bint _is_frozen
    cdef public dict _depth_sig_cache  # Cache for get_depth_signature


    def __init__(
        self,
        opcode: int | None = None,
        left: AstBase | None = None,
        right: AstBase | None = None,
        dst: AstBase | None = None,
    ):
        super().__init__()
        self.opcode = opcode
        # if left is not None:
        #     self.left = left
        # if right is not None:
        #     self.right = right
        # if dst is not None:
        #     self.dst = dst
        self.left = left
        self.right = right
        self.dst = dst
        self.mop = None
        self.dst_mop = None

        self.opcodes = []
        self.is_candidate_ok = <bint>False

        self.leafs = []
        self.leafs_by_name = {}

        self.ast_index = 0
        self.sub_ast_info_by_index = {}

        self.func_name = ""
        self._is_frozen = <bint>False  # All newly created nodes are mutable by default
        self._depth_sig_cache = {}  # Cache for get_depth_signature

    @_compat.override
    def is_frozen(self) -> bool:
        return bool(self._is_frozen)

    @_compat.override
    def freeze(self):
        """Recursively freezes this node and all its children."""
        if self._is_frozen:
            return
        self._is_frozen = <bint>True
        if hasattr(self, "left") and self.left:
            self.left.freeze()
        if hasattr(self, "right") and self.right:
            self.right.freeze()
        if hasattr(self, "dst") and self.dst:
            self.dst.freeze()

    @property
    def size(self):
        return self.mop.d.d.size if self.mop else 0

    def compute_sub_ast(self):
        self.sub_ast_info_by_index = {}
        assert self.ast_index is not None
        self.sub_ast_info_by_index[self.ast_index] = AstInfo(self, 1)

        if self.left is not None:
            self.left.compute_sub_ast()
            for ast_index, ast_info in self.left.sub_ast_info_by_index.items():
                if ast_index not in self.sub_ast_info_by_index.keys():
                    self.sub_ast_info_by_index[ast_index] = AstInfo(ast_info.ast, 0)
                self.sub_ast_info_by_index[
                    ast_index
                ].number_of_use += ast_info.number_of_use

        if self.right is not None:
            self.right.compute_sub_ast()
            for ast_index, ast_info in self.right.sub_ast_info_by_index.items():
                if ast_index not in self.sub_ast_info_by_index.keys():
                    self.sub_ast_info_by_index[ast_index] = AstInfo(ast_info.ast, 0)
                self.sub_ast_info_by_index[
                    ast_index
                ].number_of_use += ast_info.number_of_use

    def get_information(self):
        leaf_info_list = []
        cst_list = []
        opcode_list = []
        self.compute_sub_ast()

        for _, ast_info in self.sub_ast_info_by_index.items():
            if (ast_info.ast.mop is not None) and (
                ast_info.ast.mop.t != ida_hexrays.mop_z
            ):
                if ast_info.ast.is_leaf():
                    if ast_info.ast.is_constant():
                        cst_list.append(ast_info.ast.mop.nnn.value)
                    else:
                        leaf_info_list.append(ast_info)
                else:
                    ast_node = typing.cast(AstNode, ast_info.ast)
                    opcode_list += [ast_node.opcode] * ast_info.number_of_use

        return leaf_info_list, cst_list, opcode_list

    def __getitem__(self, k: str) -> AstLeaf:
        return self.leafs_by_name[k]

    def get_leaf_list(self) -> list[AstLeaf]:
        leafs = []
        if self.left is not None:
            leafs += self.left.get_leaf_list()
        if self.right is not None:
            leafs += self.right.get_leaf_list()
        return leafs

    def add_leaf(self, leaf_name: str, leaf_mop: ida_hexrays.mop_t):
        leaf = AstLeaf(leaf_name)
        leaf.mop = leaf_mop
        self.leafs.append(leaf)
        self.leafs_by_name[leaf_name] = leaf

    def add_constant_leaf(self, leaf_name: str, cst_value: int, cst_size: int):
        masked_value = cst_value & AND_TABLE[cst_size]
        cst_mop = get_constant_mop(masked_value, cst_size)
        self.add_leaf(leaf_name, cst_mop)

    def check_pattern_and_copy_mops(
        self, ast: AstNode | AstLeaf, read_only: bool = False
    ) -> bool:
        if not read_only:
            self.reset_mops()
        if logger.debug_on:
            logger.debug(
                "AstNode.check_pattern_and_copy_mops from %r",
                ast,
            )
        is_matching_shape = self._copy_mops_from_ast(ast, read_only)
        if not is_matching_shape:
            return False
        return self._check_implicit_equalities()

    def reset_mops(self):
        self.mop = None
        if self.left is not None:
            self.left.reset_mops()
        if self.right is not None:
            self.right.reset_mops()

    def _copy_mops_from_ast(
        self, other: AstNode | AstLeaf, read_only: bool = False
    ) -> bool:
        if not other.is_node():
            return False
        other = typing.cast(AstNode, other)
        if self.opcode != other.opcode:
            return False

        if not read_only:
            self.mop = other.mop
            self.dst_mop = other.dst_mop
            self.dest_size = other.dest_size
            self.ea = other.ea

        if logger.debug_on:
            logger.debug(
                "AstNode._copy_mops_from_ast: self.left: %r, other.left: %r",
                self.left,
                other.left,
            )
        if self.left is not None and other.left is not None:
            if not self.left._copy_mops_from_ast(other.left, read_only):
                return False
        if logger.debug_on:
            logger.debug(
                "AstNode._copy_mops_from_ast: self.right: %r, other.right: %r",
                self.right,
                other.right,
            )
        if self.right is not None and other.right is not None:
            if not self.right._copy_mops_from_ast(other.right, read_only):
                return False
        return True

    def _check_implicit_equalities(self) -> bool:
        self.leafs = self.get_leaf_list()
        self.leafs_by_name = {}
        self.is_candidate_ok = <bint>True

        for leaf in self.leafs:
            ref_leaf = self.leafs_by_name.get(leaf.name)
            if ref_leaf is not None and leaf.mop is not None:
                if not equal_mops_ignore_size(ref_leaf.mop, leaf.mop):
                    self.is_candidate_ok = <bint>False
            self.leafs_by_name[leaf.name] = leaf
        return bool(self.is_candidate_ok)

    def update_leafs_mop(
        self,
        other: AstNode | AstProxy,
        other2: AstNode | AstProxy | None = None,
    ) -> bool:
        self.leafs = self.get_leaf_list()
        all_leafs_found = True
        for leaf in self.leafs:
            if other is not None and leaf.name in other.leafs_by_name:
                leaf.mop = other.leafs_by_name[leaf.name].mop
            elif other2 is not None and leaf.name in other2.leafs_by_name:
                leaf.mop = other2.leafs_by_name[leaf.name].mop
            else:
                all_leafs_found = False
        return all_leafs_found

    def create_mop(self, ea: int) -> ida_hexrays.mop_t:
        new_ins = self.create_minsn(ea)
        new_ins_mop = ida_hexrays.mop_t()
        new_ins_mop.create_from_insn(new_ins)
        return new_ins_mop

    def create_minsn(self, ea: int, dest=None) -> ida_hexrays.minsn_t:
        new_ins = ida_hexrays.minsn_t(ea)
        new_ins.opcode = self.opcode

        if self.left is not None:
            new_ins.l = self.left.create_mop(ea)
            if self.right is not None:
                new_ins.r = self.right.create_mop(ea)

        new_ins.d = ida_hexrays.mop_t()

        if self.left is not None:
            new_ins.d.size = new_ins.l.size
        if dest is not None:
            new_ins.d = dest
        return new_ins

    def get_pattern(self) -> str:
        nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
        if nb_operands == 0:
            return "AstNode({0})".format(OPCODES_INFO[self.opcode]["name"])
        elif nb_operands == 1 and self.left is not None:
            return "AstNode(m_{0}, {1})".format(
                OPCODES_INFO[self.opcode]["name"], self.left.get_pattern()
            )
        elif nb_operands == 2 and self.left is not None and self.right is not None:
            return "AstNode(m_{0}, {1}, {2})".format(
                OPCODES_INFO[self.opcode]["name"],
                self.left.get_pattern(),
                self.right.get_pattern(),
            )
        else:
            raise ValueError(f"Invalid number of operands: {nb_operands}")

    def evaluate_with_leaf_info(
        self, leafs_info: list[AstInfo], leafs_value: list[int]
    ) -> int:
        return _DEFAULT_AST_EVALUATOR.evaluate_with_leaf_info(self, leafs_info, leafs_value)

    def evaluate(self, dict_index_to_value: dict[int, int]) -> int:
        return _DEFAULT_AST_EVALUATOR.evaluate(self, dict_index_to_value)

    def get_depth_signature(self, int depth):
        # Check cache first (fast path for frozen nodes)
        cdef list cached = self._depth_sig_cache.get(depth)
        if cached is not None:
            return cached

        cdef list result
        cdef list tmp
        cdef int nb_operands

        if depth == 1:
            result = [str(self.opcode)]
        else:
            tmp = []
            nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
            if (nb_operands >= 1) and self.left is not None:
                tmp += self.left.get_depth_signature(depth - 1)
            else:
                tmp += _get_n_sig(depth - 2)
            if (nb_operands >= 2) and self.right is not None:
                tmp += self.right.get_depth_signature(depth - 1)
            else:
                tmp += _get_n_sig(depth - 2)
            result = tmp

        # Cache the result for frozen nodes
        if self._is_frozen:
            self._depth_sig_cache[depth] = result
        return result

    def __str__(self):
        try:
            nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
            if "symbol" in OPCODES_INFO[self.opcode].keys():
                if nb_operands == 0:
                    return "{0}()".format(OPCODES_INFO[self.opcode]["symbol"])
                elif nb_operands == 1:
                    return "{0}({1})".format(
                        OPCODES_INFO[self.opcode]["symbol"], self.left
                    )
                elif nb_operands == 2:
                    if OPCODES_INFO[self.opcode]["symbol"] not in Z3_SPECIAL_OPERANDS:
                        return "({1} {0} {2})".format(
                            OPCODES_INFO[self.opcode]["symbol"], self.left, self.right
                        )
                    else:
                        return "{0}({1}, {2})".format(
                            OPCODES_INFO[self.opcode]["symbol"], self.left, self.right
                        )
            else:
                if nb_operands == 0:
                    return "{0}()".format(OPCODES_INFO[self.opcode]["name"])
                elif nb_operands == 1:
                    return "{0}({1})".format(
                        OPCODES_INFO[self.opcode]["name"], self.left
                    )
                elif nb_operands == 2:
                    return "{0}({1}, {2})".format(
                        OPCODES_INFO[self.opcode]["name"], self.left, self.right
                    )
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstNode: {0}".format(e))
        return "Error_AstNode"

    def __repr__(self):
        op_str = opcode_to_string(self.opcode) if self.opcode is not None else "None"
        return f"AstNode({op_str}, left={self.left}, right={self.right})"

    cpdef AstNode clone(self):
        """Fast, C-level recursive implementation of clone."""
        # Create a new instance without calling Python's __init__
        cdef AstNode new_node = AstNode.__new__(AstNode)
        # Call __init__ to set up all lists/dicts correctly
        new_node.__init__(self.opcode)

        # Manually copy attributes
        # new_node.opcode = self.opcode
        new_node.mop = self.mop
        new_node.dst_mop = self.dst_mop
        new_node.dest_size = self.dest_size
        new_node.ea = self.ea
        new_node.ast_index = self.ast_index
        new_node.func_name = self.func_name

        # Create shallow copies of collections. This is safe because the
        # items inside (other AST nodes) will be cloned recursively below.
        new_node.opcodes = self.opcodes.copy()
        new_node.leafs = self.leafs.copy()
        new_node.leafs_by_name = self.leafs_by_name.copy()
        # Recursively clone children using the fast path
        # The `is not None` check is crucial
        # if hasattr(self, "left") and self.left is not None:
        #     new_node.left = self.left.clone()
        # if hasattr(self, "right") and self.right is not None:
        #     new_node.right = self.right.clone()
        # if hasattr(self, "dst") and self.dst is not None:
        #     new_node.dst = self.dst.clone()
        new_node.left = self.left.clone() if self.left is not None else None
        new_node.right = self.right.clone() if self.right is not None else None
        new_node.dst = self.dst.clone() if self.dst is not None else None

        # Initialize transient state for the new clone
        new_node.is_candidate_ok = <bint>False
        new_node.leafs = []
        new_node.leafs_by_name = {}
        new_node.opcodes = []
        new_node.sub_ast_info_by_index = {}
        new_node._depth_sig_cache = {}  # Fresh cache for cloned object
        new_node._is_frozen = <bint>False
        return new_node

    @_compat.override
    def is_node(self):
        return True

    @_compat.override
    def is_leaf(self):
        # An AstNode is not a leaf, so returns False
        return False

    @_compat.override
    def is_constant(self):
        return False


cdef class AstLeaf(AstBase):
    cdef public object name
    cdef public object z3_var
    cdef public object z3_var_name
    cdef public bint _is_frozen
    cdef public dict _depth_sig_cache  # Cache for get_depth_signature

    def __init__(self, name):
        self.name = name
        self.ast_index: None

        self.mop = None
        self.z3_var = None
        self.z3_var_name = NOT_GIVEN

        self.dest_size = None
        self.ea = None
        self._is_frozen = <bint>False  # All newly created nodes are mutable by default
        self.sub_ast_info_by_index = {}
        self._depth_sig_cache = {}  # Cache for get_depth_signature

    @_compat.override
    def is_frozen(self) -> bool:
        return bool(self._is_frozen)

    @_compat.override
    def freeze(self):
        """Recursively freezes this node and all its children."""
        if self._is_frozen:
            return
        self._is_frozen = <bint>True

    @_compat.override
    def is_node(self):
        return False

    @_compat.override
    def is_leaf(self):
        return True

    @_compat.override
    def is_constant(self):
        if self.mop is None:
            return False
        return self.mop.t == ida_hexrays.mop_n

    cpdef AstLeaf clone(self):
        """Fast, C-level cloner for AstLeaf instances."""
        cdef AstLeaf new_leaf = AstLeaf.__new__(AstLeaf)
        # Call __init__ to set up name and defaults
        new_leaf.__init__(self.name)
        # Manually copy attribute
        new_leaf.ast_index = self.ast_index
        new_leaf.mop = self.mop
        new_leaf.dest_size = self.dest_size
        new_leaf.ea = self.ea

        # Initialize transient state
        new_leaf.z3_var = None
        new_leaf._depth_sig_cache = {}  # Fresh cache for cloned object
        return new_leaf

    def __getitem__(self, name: str) -> AstLeaf:
        if name == self.name:
            return self
        raise KeyError

    @property
    def size(self):
        return self.mop.size if self.mop else 0

    @property
    def dst_mop(self):
        return self.mop

    @dst_mop.setter
    def dst_mop(self, mop):
        self.mop = mop

    @property
    def value(self):
        if self.is_constant() and self.mop is not None:
            return self.mop.nnn.value
        else:
            return None

    def compute_sub_ast(self):
        self.sub_ast_info_by_index = {}
        assert self.ast_index is not None
        self.sub_ast_info_by_index[self.ast_index] = AstInfo(self, 1)

    def get_information(self):
        # Just here to allow calling get_information on either a AstNode or AstLeaf
        return [], [], []

    def get_leaf_list(self):
        return [self]

    def create_mop(self, ea):
        # 1. Constant operands can keep using the shared cache
        if self.is_constant() and self.value is not None:
            # TODO: is this right?
            size = self.dest_size if self.dest_size is not None else self.size
            if logger.debug_on:
                logger.debug(
                    "AstLeaf.create_mop: Constant operand @ 0x%x: %s, size: %s, dest_size: %s, equal? %s",
                    ea,
                    self.value,
                    size,
                    self.dest_size,
                    size == self.dest_size,
                )
            val = get_constant_mop(self.value, size)
            if logger.debug_on:
                logger.debug(
                    "AstLeaf.create_mop: Constant operand reused: %s",
                    val,
                    extra={"ea": hex(ea)},
                )
            return val

        if self.mop is None:
            logger.error(
                "%r mop is None in create_mop for 0x%x",
                self,
                ea,
            )
            raise AstEvaluationException(
                f"{repr(self)}'s mop is None in create_mop for {hex(ea)}"
            )

        # 2. Otherwise, we need to create a new mop
        new_mop = ida_hexrays.mop_t()
        new_mop.assign(self.mop)
        return new_mop  # duplicates the C++ object

    def update_leafs_mop(self, other: AstNode, other2: AstNode | None = None):
        source_leaf = None
        if other is not None and self.name in other.leafs_by_name:
            source_leaf = other.leafs_by_name[self.name]
        elif other2 is not None and self.name in other2.leafs_by_name:
            source_leaf = other2.leafs_by_name[self.name]

        if source_leaf is None:
            return False

        # Copy mop if available
        if source_leaf.mop is not None:
            self.mop = source_leaf.mop
            return True

        # For computed constants (e.g., c_res from constraints), copy the value
        # so that create_mop can generate a constant mop
        source_value = getattr(source_leaf, 'value', None)
        if source_value is None:
            source_value = getattr(source_leaf, 'expected_value', None)
        if source_value is not None:
            self.value = source_value
            return True

        return False

    def check_pattern_and_copy_mops(self, ast, read_only: bool = False):
        if not read_only:
            self.reset_mops()
        is_matching_shape = self._copy_mops_from_ast(ast, read_only)

        if not is_matching_shape:
            return False
        return self._check_implicit_equalities()

    def reset_mops(self):
        self.z3_var = None
        self.z3_var_name = NOT_GIVEN
        self.mop = None

    def _copy_mops_from_ast(self, other, read_only: bool = False):
        if other.mop is None:
            if logger.debug_on:
                logger.debug(
                    "AstLeaf._copy_mops_from_ast: other %r's mop is None",
                    other,
                )
            return False
        if logger.debug_on:
            logger.debug(
                "AstLeaf._copy_mops_from_ast: other %r's mop %s is not None",
                other,
                format_mop_t(other.mop),
            )
        if not read_only:
            self.mop = other.mop
        return True

    @staticmethod
    def _check_implicit_equalities():
        # An AstLeaf does not have any implicit equalities to be checked, so we always returns True
        return True

    def get_pattern(self):
        if self.is_constant() and self.mop is not None:
            return "AstConstant('{0}', {0})".format(self.mop.nnn.value)
        if self.ast_index is not None:
            return "AstLeaf('x_{0}')".format(self.ast_index)
        if self.name is not None:
            return "AstLeaf('{0}')".format(self.name)

    def evaluate_with_leaf_info(self, leafs_info, leafs_value):
        return _DEFAULT_AST_EVALUATOR.evaluate_with_leaf_info(self, leafs_info, leafs_value)

    def evaluate(self, dict_index_to_value):
        return _DEFAULT_AST_EVALUATOR.evaluate(self, dict_index_to_value)

    def get_depth_signature(self, int depth):
        # Check cache first
        cdef list cached = self._depth_sig_cache.get(depth)
        if cached is not None:
            return cached

        cdef list result
        if depth == 1:
            result = ["C"] if self.is_constant() else ["L"]
        else:
            result = _get_n_sig(depth - 1)

        # Cache the result for frozen nodes
        if self._is_frozen:
            self._depth_sig_cache[depth] = result
        return result

    def __str__(self):
        try:
            if self.is_constant() and self.mop is not None:
                return "{0}".format(hex(self.mop.nnn.value))
            if self.z3_var_name is not NOT_GIVEN:
                return self.z3_var_name
            if self.ast_index is not None:
                return "x_{0}".format(self.ast_index)
            if self.mop is not None:
                return format_mop_t(self.mop)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstLeaf: {0}".format(e))
            return "Error_AstLeaf"

    def __repr__(self):
        return f"AstLeaf('{str(self)}')"


cdef class AstConstant(AstLeaf):
    cdef public object expected_value
    cdef public object expected_size

    def __init__(self, name, expected_value=None, expected_size=None):
        super().__init__(name)
        self.expected_value = expected_value
        self.expected_size = expected_size

    @property
    def value(self):
        if self.mop is not None and self.mop.t == ida_hexrays.mop_n:
            return self.mop.nnn.value
        # Fall back to expected_value for computed constants (e.g., c_res from constraints)
        return self.expected_value

    @_compat.override
    def is_constant(self) -> bool:
        # An AstConstant is always constant, so return True
        return True

    def _copy_mops_from_ast(self, other, read_only: bool = False):
        if other.mop is not None and other.mop.t != ida_hexrays.mop_n:
            if logger.debug_on:
                logger.debug(
                    "AstConstant._copy_mops_from_ast: other.mop is not a constant: %r",
                    other.mop,
                )
            return False

        if logger.debug_on:
            logger.debug(
                "AstConstant._copy_mops_from_ast: other %r's mop %s is a constant",
                other,
                format_mop_t(other.mop),
            )
        if not read_only:
            self.mop = other.mop
        if self.expected_value is None:
            if not read_only:
                self.expected_value = other.mop.nnn.value
                self.expected_size = other.mop.size
            else:
                return True
        return self.expected_value == other.mop.nnn.value

    def evaluate(self, dict_index_to_value=None):
        if self.mop is not None and self.mop.t == ida_hexrays.mop_n:
            return self.mop.nnn.value
        return self.expected_value

    def get_depth_signature(self, int depth):
        # Check cache first (inherited from AstLeaf)
        cdef list cached = self._depth_sig_cache.get(depth)
        if cached is not None:
            return cached

        cdef list result
        if depth == 1:
            result = ["C"]
        else:
            result = _get_n_sig(depth - 1)

        # Cache the result for frozen nodes
        if self._is_frozen:
            self._depth_sig_cache[depth] = result
        return result

    @_compat.override
    def __str__(self):
        try:
            if self.mop is not None and self.mop.t == ida_hexrays.mop_n:
                return "0x{0:x}".format(self.mop.nnn.value)
            if getattr(self, "expected_value", None) is not None:
                return "0x{0:x}".format(self.expected_value)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstConstant: {0}".format(e))
            return "Error_AstConstant"

    @_compat.override
    def __repr__(self):
        return f"AstConstant({str(self)})"

    def update_leafs_mop(self, other: AstNode, other2: AstNode | None = None):
        """Override to store computed value in expected_value instead of value."""
        source_leaf = None
        if other is not None and self.name in other.leafs_by_name:
            source_leaf = other.leafs_by_name[self.name]
        elif other2 is not None and self.name in other2.leafs_by_name:
            source_leaf = other2.leafs_by_name[self.name]

        if source_leaf is None:
            return False

        # Copy mop if available
        if source_leaf.mop is not None:
            self.mop = source_leaf.mop
            # Also update expected_value from the mop
            if source_leaf.mop.t == ida_hexrays.mop_n:
                self.expected_value = source_leaf.mop.nnn.value
                self.expected_size = source_leaf.mop.size
            return True

        # For computed constants, copy to expected_value
        source_value = getattr(source_leaf, 'value', None)
        if source_value is None:
            source_value = getattr(source_leaf, 'expected_value', None)
        if source_value is not None:
            self.expected_value = source_value
            # Try to get size too
            source_size = getattr(source_leaf, 'expected_size', None)
            if source_size is None:
                source_size = getattr(source_leaf, 'dest_size', None)
            if source_size is not None:
                self.expected_size = source_size
            return True

        return False

    cpdef AstConstant clone(self):
        """Fast, C-level cloner for AstConstant instances."""
        cdef AstConstant new_const = AstConstant.__new__(AstConstant)
        # Call __init__ to set up name and expected values
        new_const.__init__(self.name, self.expected_value, self.expected_size)

        # Copy AstLeaf attributes
        # new_const.name = self.name
        new_const.ast_index = self.ast_index
        new_const.mop = self.mop
        new_const.dest_size = self.dest_size
        new_const.ea = self.ea

        # Initialize transient state
        new_const.z3_var = None
        new_const.z3_var_name = NOT_GIVEN
        new_const.sub_ast_info_by_index = {}
        new_const._depth_sig_cache = {}  # Fresh cache for cloned object
        new_const._is_frozen = <bint>False
        return new_const


# class AstEvaluator:
#     """
#     Pure-Python evaluator for AST nodes. Extracted from AstNode/AstLeaf methods
#     to centralize evaluation logic.
#     """

#     def evaluate_with_leaf_info(self, node, leafs_info, leafs_value):
#         dict_index_to_value = {}
#         for leaf_info, leaf_value in zip(leafs_info, leafs_value):
#             if leaf_info.ast.ast_index is not None:
#                 dict_index_to_value[leaf_info.ast.ast_index] = leaf_value
#         return self.evaluate(node, dict_index_to_value)

#     def evaluate(self, node, dict_index_to_value):
#         if isinstance(node, AstNode):
#             return self._eval_node(node, dict_index_to_value)
#         if isinstance(node, AstLeaf):
#             return self._eval_leaf(node, dict_index_to_value)
#         if isinstance(node, AstProxy):
#             return self.evaluate(node._target, dict_index_to_value)
#         raise AstEvaluationException(f"Unsupported AST node type: {type(node).__name__}")

#     def _eval_leaf(self, leaf, dict_index_to_value):
#         # AstConstant: prefer concrete mop value, otherwise fall back to expected_value
#         if isinstance(leaf, AstConstant):
#             if leaf.mop is not None and leaf.mop.t == ida_hexrays.mop_n:
#                 return leaf.mop.nnn.value
#             return leaf.expected_value

#         if leaf.is_constant() and leaf.mop is not None:
#             return leaf.mop.nnn.value
#         assert leaf.ast_index is not None
#         return dict_index_to_value.get(leaf.ast_index)

#     def _eval_node(self, node, dict_index_to_value):
#         if node.ast_index in dict_index_to_value:
#             return dict_index_to_value[node.ast_index]
#         if node.dest_size is None:
#             raise ValueError("dest_size is None")

#         res_mask = AND_TABLE[node.dest_size]

#         if node.left is None:
#             raise ValueError(f"left is None for opcode: {node.opcode}")

#         binary_opcodes = {
#             ida_hexrays.m_add,
#             ida_hexrays.m_sub,
#             ida_hexrays.m_mul,
#             ida_hexrays.m_udiv,
#             ida_hexrays.m_sdiv,
#             ida_hexrays.m_umod,
#             ida_hexrays.m_smod,
#             ida_hexrays.m_or,
#             ida_hexrays.m_and,
#             ida_hexrays.m_xor,
#             ida_hexrays.m_shl,
#             ida_hexrays.m_shr,
#             ida_hexrays.m_sar,
#             ida_hexrays.m_cfadd,
#             ida_hexrays.m_ofadd,
#             ida_hexrays.m_seto,
#             ida_hexrays.m_setnz,
#             ida_hexrays.m_setz,
#             ida_hexrays.m_setae,
#             ida_hexrays.m_setb,
#             ida_hexrays.m_seta,
#             ida_hexrays.m_setbe,
#             ida_hexrays.m_setg,
#             ida_hexrays.m_setge,
#             ida_hexrays.m_setl,
#             ida_hexrays.m_setle,
#             ida_hexrays.m_setp,
#         }

#         if node.opcode in binary_opcodes and node.right is None:
#             raise ValueError("right is None for binary opcode: {0}".format(node.opcode))

#         if node.opcode == ida_hexrays.m_mov:
#             return (self.evaluate(node.left, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_neg:
#             return (-self.evaluate(node.left, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_lnot:
#             return self.evaluate(node.left, dict_index_to_value) != 0
#         elif node.opcode == ida_hexrays.m_bnot:
#             return (self.evaluate(node.left, dict_index_to_value) ^ res_mask) & res_mask
#         elif node.opcode == ida_hexrays.m_xds:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             return signed_to_unsigned(left_value_signed, node.dest_size) & res_mask
#         elif node.opcode == ida_hexrays.m_xdu:
#             return (self.evaluate(node.left, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_low:
#             return (self.evaluate(node.left, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_high:
#             if node.left.dest_size is None:
#                 raise ValueError("left.dest_size is None for m_high")
#             shift_bits = node.dest_size * 8 if node.dest_size is not None else 0
#             return (self.evaluate(node.left, dict_index_to_value) >> shift_bits) & res_mask
#         elif node.opcode == ida_hexrays.m_add and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) + self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_sub and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) - self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_mul and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) * self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_udiv and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) // self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_sdiv and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) // self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_umod and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) % self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_smod and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) % self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_or and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) | self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_and and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) & self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_xor and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) ^ self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_shl and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) << self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_shr and node.right is not None:
#             return (self.evaluate(node.left, dict_index_to_value) >> self.evaluate(node.right, dict_index_to_value)) & res_mask
#         elif node.opcode == ida_hexrays.m_sar and node.right is not None:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             res_signed = left_value_signed >> self.evaluate(node.right, dict_index_to_value)
#             return signed_to_unsigned(res_signed, node.dest_size) & res_mask
#         elif node.opcode == ida_hexrays.m_cfadd and node.right is not None:
#             tmp = get_add_cf(
#                 self.evaluate(node.left, dict_index_to_value),
#                 self.evaluate(node.right, dict_index_to_value),
#                 node.left.dest_size,
#             )
#             return tmp & res_mask
#         elif node.opcode == ida_hexrays.m_ofadd and node.right is not None:
#             tmp = get_add_of(
#                 self.evaluate(node.left, dict_index_to_value),
#                 self.evaluate(node.right, dict_index_to_value),
#                 node.left.dest_size,
#             )
#             return tmp & res_mask
#         elif node.opcode == ida_hexrays.m_sets:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             res = 1 if left_value_signed < 0 else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_seto and node.right is not None:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             right_value_signed = unsigned_to_signed(
#                 self.evaluate(node.right, dict_index_to_value), node.right.dest_size
#             )
#             sub_overflow = get_sub_of(
#                 left_value_signed, right_value_signed, node.left.dest_size
#             )
#             return sub_overflow & res_mask
#         elif node.opcode == ida_hexrays.m_setnz and node.right is not None:
#             res = 1 if self.evaluate(node.left, dict_index_to_value) != self.evaluate(node.right, dict_index_to_value) else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setz and node.right is not None:
#             res = 1 if self.evaluate(node.left, dict_index_to_value) == self.evaluate(node.right, dict_index_to_value) else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setae and node.right is not None:
#             res = 1 if self.evaluate(node.left, dict_index_to_value) >= self.evaluate(node.right, dict_index_to_value) else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setb and node.right is not None:
#             res = 1 if self.evaluate(node.left, dict_index_to_value) < self.evaluate(node.right, dict_index_to_value) else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_seta and node.right is not None:
#             res = 1 if self.evaluate(node.left, dict_index_to_value) > self.evaluate(node.right, dict_index_to_value) else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setbe and node.right is not None:
#             res = 1 if self.evaluate(node.left, dict_index_to_value) <= self.evaluate(node.right, dict_index_to_value) else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setg and node.right is not None:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             right_value_signed = unsigned_to_signed(
#                 self.evaluate(node.right, dict_index_to_value), node.right.dest_size
#             )
#             res = 1 if left_value_signed > right_value_signed else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setge and node.right is not None:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             right_value_signed = unsigned_to_signed(
#                 self.evaluate(node.right, dict_index_to_value), node.right.dest_size
#             )
#             res = 1 if left_value_signed >= right_value_signed else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setl and node.right is not None:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             right_value_signed = unsigned_to_signed(
#                 self.evaluate(node.right, dict_index_to_value), node.right.dest_size
#             )
#             res = 1 if left_value_signed < right_value_signed else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setle and node.right is not None:
#             left_value_signed = unsigned_to_signed(
#                 self.evaluate(node.left, dict_index_to_value), node.left.dest_size
#             )
#             right_value_signed = unsigned_to_signed(
#                 self.evaluate(node.right, dict_index_to_value), node.right.dest_size
#             )
#             res = 1 if left_value_signed <= right_value_signed else 0
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_setp and node.right is not None:
#             res = get_parity_flag(
#                 self.evaluate(node.left, dict_index_to_value),
#                 self.evaluate(node.right, dict_index_to_value),
#                 node.left.dest_size,
#             )
#             return res & res_mask
#         elif node.opcode == ida_hexrays.m_call:
#             if logger.debug_on:
#                 logger.debug(
#                     "evaluate m_call: ast_index=%s, dest_size=%s, callee=%s, args=%s",
#                     node.ast_index,
#                     node.dest_size,
#                     node.left,
#                     node.right,
#                 )
#             return 0 & res_mask
#         else:
#             raise AstEvaluationException(
#                 "Can't evaluate opcode: {0}".format(node.opcode)
#             )


_DEFAULT_AST_EVALUATOR = AstEvaluator()


cdef class AstProxy(AstBase):
    cdef public AstBase _target
    cdef public bint _mutable

    def __init__(self, target_ast: AstBase):
        self._target = target_ast
        self._mutable = <bint>False

    def _ensure_mutable(self):
        """
        Ensures the target is mutable. If the target is frozen, clone it and
        replace our internal reference with the new, mutable clone.
        Skips cloning if already mutable.
        """
        if not self._mutable:
            if self._target.is_frozen():
                # Clone only if frozen (i.e., shared)
                self._target = self._target.clone()
            # Mark as mutable to prevent future clones
            self._mutable = <bint>True

    def __getattr__(self, name):
        """
        Handles all read access to attributes (e.g., proxy.opcode, proxy.left).
        """
        # Forward read requests directly to the target (shared or cloned).
        return getattr(self._target, name)

    def __setattr__(self, name, value):
        """
        Handles all write access to attributes (e.g., proxy.ast_index = 5).
        """
        if name == "_target" or name == "_mutable":
            # Special case to allow initialization of the proxy itself.
            self.__dict__["_target"] = value
            return

        # 1. Trigger the clone-on-write check.
        self._ensure_mutable()

        # 2. Perform the write on the (now guaranteed to be mutable) target.
        setattr(self._target, name, value)

    # You might need to proxy other magic methods if your code uses them
    # For example, if you use AstNode as a dict:
    def __getitem__(self, key):
        getitem = getattr(self._target, "__getitem__", None)
        if getitem is None:
            raise AttributeError(
                f"Object of type {type(self._target)} does not support __getitem__"
            )
        return getitem(key)

    def __setitem__(self, key, value):
        setitem = getattr(self._target, "__setitem__", None)
        if setitem is None:
            raise AttributeError(
                f"Object of type {type(self._target)} does not support __setitem__"
            )
        self._ensure_mutable()
        setitem(key, value)

    # ------------------------------------------------------------------
    # Transparent attribute forwarding with sane fallback.
    # ------------------------------------------------------------------

    def __getattribute__(self, name):  # noqa: D401, ANN001
        """Forward *all* attribute access to the wrapped target when:
        1) the attribute is not private to the proxy itself, and
        2) the value obtained from the proxy's own namespace is *None*.

        This retains the cheap class-level default attributes coming from
        AstBase (all set to None) while still exposing the real runtime
        values stored in the wrapped AST object.
        """

        # Fast-path: internal/private attributes stay local.
        if name.startswith("_"):
            return super().__getattribute__(name)

        try:
            val = super().__getattribute__(name)
        except AttributeError:
            # Attribute not present on proxy → delegate unconditionally.
            return getattr(super().__getattribute__("_target"), name)

        # If the proxy's value is a meaningless placeholder (None) but the
        # underlying object has a better value, return the latter instead.
        if val is None:
            target = super().__getattribute__("_target")
            return getattr(target, name)
        return val

    def is_frozen(self) -> bool:
        return self._target.is_frozen()

    @_compat.override
    def clone(self) -> AstBase:
        return AstProxy(self._target.clone())

    @_compat.override
    def freeze(self) -> None:
        self._target.freeze()

    @_compat.override
    def is_node(self) -> bool:
        return self._target.is_node()

    @_compat.override
    def is_leaf(self) -> bool:
        return self._target.is_leaf()

    @_compat.override
    def is_constant(self) -> bool:
        return self._target.is_constant()

    @_compat.override
    def compute_sub_ast(self) -> None:
        self._target.compute_sub_ast()

    @_compat.override
    def get_leaf_list(self) -> list[AstLeaf]:
        return self._target.get_leaf_list()

    @_compat.override
    def reset_mops(self) -> None:
        self._target.reset_mops()

    @_compat.override
    def _copy_mops_from_ast(self, other: AstBase) -> bool:
        return self._target._copy_mops_from_ast(other)

    @_compat.override
    def create_mop(self, ea: int) -> ida_hexrays.mop_t:
        return self._target.create_mop(ea)

    @_compat.override
    def get_pattern(self) -> str:
        return self._target.get_pattern()

    @_compat.override
    def evaluate(self, dict_index_to_value: dict[int, int]) -> int:
        return self._target.evaluate(dict_index_to_value)

    @_compat.override
    def get_depth_signature(self, depth: int) -> list[str]:
        return self._target.get_depth_signature(depth)

    @_compat.override
    def __str__(self):
        return f"AstProxy({self._target.__class__.__name__}({str(self._target)}))"

    @_compat.override
    def __repr__(self):
        return f"AstProxy({repr(self._target)})"

    # Explicitly forward critical leaf data that callers expect to access
    # directly.  Without these properties Python finds the *class*-level
    # attribute defined in AstBase (value = None) and never triggers
    # __getattr__, so evaluators see a leaf with no mop.

    # ‑-- Mop -------------------------------------------------------------
    @property
    def mop(self):  # type: ignore[override]
        return self._target.mop

    @mop.setter
    def mop(self, value):  # noqa: ANN001
        self._ensure_mutable()
        self._target.mop = value

    # Convenience setters for a few commonly mutated fields
    @property
    def dest_size(self):  # type: ignore[override]
        return self._target.dest_size

    @dest_size.setter
    def dest_size(self, value):  # noqa: ANN001
        self._ensure_mutable()
        self._target.dest_size = value

    @property
    def ea(self):  # type: ignore[override]
        return self._target.ea

    @ea.setter
    def ea(self, value):  # noqa: ANN001
        self._ensure_mutable()
        self._target.ea = value

    @property
    def ast_index(self):  # type: ignore[override]
        return self._target.ast_index

    @ast_index.setter
    def ast_index(self, value):  # noqa: ANN001
        self._ensure_mutable()
        self._target.ast_index = value


cdef class AstBuilderContext:
    """
    Manages the state during the recursive construction of an AST.
    This avoids passing multiple related arguments through the recursion
    and provides a clean way to store the lookup dictionary.
    """
    cdef public list[AstBase] unique_asts
    cdef public dict[tuple[int, str], int] mop_key_to_index

    def __cinit__(self):
        self.unique_asts = []
        self.mop_key_to_index = {}


def get_mop_key(mop: ida_hexrays.mop_t) -> tuple:
    """
    Generates a fast, hashable key for a `mop_t` using the structural hash.
    Avoids `dstr()` entirely and ignores SSA valnum differences.
    """
    t = mop.t
    sz = mop.size
    try:
        h = int(structural_mop_hash(mop, 0))
        return (t, sz, h)
    except Exception:
        # Fallback: rely on cheap structural fields only; still avoid dstr().
        if t == ida_hexrays.mop_n:
            return (t, sz, mop.valnum, mop.nnn.value)
        elif t == ida_hexrays.mop_r:
            return (t, sz, mop.r)
        elif t == ida_hexrays.mop_d:
            # Use EA if available; do not call dstr()
            return (t, sz, mop.d.ea if mop.d else idaapi.BADADDR)
        elif t == ida_hexrays.mop_S:
            return (t, sz, mop.s.off)
        elif t == ida_hexrays.mop_v:
            return (t, sz, mop.g)
        elif t == ida_hexrays.mop_l:
            return (t, sz, mop.l.idx, mop.l.off)
        elif t == ida_hexrays.mop_b:
            return (t, sz, mop.b)
        elif t == ida_hexrays.mop_h:
            return (t, sz, mop.helper)
        elif t == ida_hexrays.mop_str:
            return (t, sz, mop.cstr)
        else:
            # Last resort: identity-based key
            return (t, sz, id(mop))


# def get_mop_key_cy(mop):
#     """
#     Generates a fast, hashable key from a mop_t's essential attributes.
#     Cython version that takes Python mop_t for compatibility.
#     """
#     cdef int t = mop.t

#     # Build base key - same logic as Python
#     key = (t, mop.size) if t != ida_hexrays.mop_n else (t, mop.size, mop.valnum)

#     if t == ida_hexrays.mop_n:
#         return key + (mop.nnn.value,)
#     elif t == ida_hexrays.mop_r:
#         return key + (mop.r,)
#     elif t == ida_hexrays.mop_d:
#         try:
#             return key + (mop.dstr(),)
#         except:
#             if mop.d:
#                 return key + (mop.d.ea,)
#             else:
#                 return key + (idaapi.BADADDR,)
#     elif t == ida_hexrays.mop_S:
#         return key + (mop.s.off,)
#     elif t == ida_hexrays.mop_v:
#         return key + (mop.g,)
#     elif t == ida_hexrays.mop_l:
#         return key + (mop.l.idx, mop.l.off)
#     elif t == ida_hexrays.mop_b:
#         return key + (mop.b,)
#     elif t == ida_hexrays.mop_h:
#         return key + (mop.helper,)
#     elif t == ida_hexrays.mop_str:
#         return key + (mop.cstr,)
#     else:
#         try:
#             return key + (mop.dstr(),)
#         except:
#             return key + (f"unsupported_mop_t_{t}",)


def mop_to_ast_internal(
    mop: ida_hexrays.mop_t, context: AstBuilderContext, root: bool = False
) -> AstBase | None:
    # Only log at root
    if root and logger.debug_on:
        logger.debug(
            "[mop_to_ast_internal] Processing root mop: %s",
            str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
        )

    # Early filter at root: only process if supported, with one exception:
    # If the root is an m_call that has no argument list (r is mop_z) we treat it
    # as transparent and attempt to build an AST from its destination operand.
    if root:
        if hasattr(mop, "d") and hasattr(mop.d, "opcode"):
            root_opcode = mop.d.opcode

            # Transparent helper call wrappers are now normalised by a
            # peephole pass (TransparentCallUnwrapRule).  No special handling
            # needed here anymore.

            if root_opcode not in MBA_RELATED_OPCODES and not is_rotate_helper_call(
                mop.d
            ):
                if logger.debug_on:
                    logger.debug(
                        "Skipping AST build for unsupported root opcode: %s",
                        opcode_to_string(root_opcode),
                    )
                return None

    # 1. Create the unique, hashable key for the current mop.
    key = get_mop_key(mop)

    # 2. Thread-local deduplication: if we've already built an AST for *this*
    #    mop during the current recursive walk, return the existing instance to
    #    avoid exponential explosion.
    if key in context.mop_key_to_index:
        existing_index = context.mop_key_to_index[key]
        return context.unique_asts[existing_index]

    # Rotate helper calls (__ROL*/__ROR*) are now inlined into plain shift/or
    # instructions by RotateHelperInlineRule (peephole, MMAT_GLBOPT1).
    # No special handling required here.

    # Helper calls that evaluate to constants are now canonicalised by
    # ConstantCallResultFoldRule (peephole GLBOPT1).

    # NEW: Build AST nodes for MBA-related opcodes (binary or unary)
    if mop.t == ida_hexrays.mop_d and mop.d.opcode in MBA_RELATED_OPCODES:
        nb_ops = OPCODES_INFO[mop.d.opcode]["nb_operands"]

        # Gather children ASTs based on operand count
        left_ast = (
            mop_to_ast_internal(mop.d.l, context) if mop.d.l is not None else None
        )
        right_ast = (
            mop_to_ast_internal(mop.d.r, context)
            if (nb_ops >= 2 and mop.d.r is not None)
            else None
        )

        # Require at least the mandatory operands; if missing, fall back to leaf
        if left_ast is None:
            # Can't build meaningful node - fallback later to leaf
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Missing mandatory operand(s) for opcode %s, will treat as leaf",
                    opcode_to_string(mop.d.opcode),
                )
        else:
            # Only use dst_ast if destination present (ternary ops like m_stx etc.)
            dst_ast = (
                mop_to_ast_internal(mop.d.d, context) if mop.d.d is not None else None
            )
            tree = AstNode(mop.d.opcode, left_ast, right_ast, dst_ast)

            # Set dest_size robustly
            if hasattr(mop, "size") and mop.size:
                tree.dest_size = mop.size
            elif hasattr(mop.d, "size") and mop.d.size:
                tree.dest_size = mop.d.size
            elif mop.d.l is not None and hasattr(mop.d.l, "size"):
                tree.dest_size = mop.d.l.size
            else:
                tree.dest_size = None

            tree.mop = mop
            tree.ea = sanitize_ea(mop.d.ea)

            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Created AstNode for opcode %s (ea=0x%X): %s",
                    opcode_to_string(mop.d.opcode),
                    mop.d.ea if hasattr(mop.d, "ea") else -1,
                    tree,
                )
            new_index = len(context.unique_asts)
            tree.ast_index = new_index
            context.unique_asts.append(tree)
            context.mop_key_to_index[key] = new_index
            return tree

    # Special handling for mop_d that wraps an m_ldc as a constant leaf
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_ldc
    ):
        # Only treat it as constant if the *source* of the ldc is itself a
        # numeric constant.  Otherwise we ignore the ldc wrapper and fall
        # back to the generic leaf logic below.
        ldc_src = mop.d.l
        if ldc_src is not None and ldc_src.t == ida_hexrays.mop_n:
            const_val = int(ldc_src.nnn.value)
            const_size = ldc_src.size

            const_leaf = AstConstant(hex(const_val), const_val, const_size)
            # Clone numeric mop to detach from Hex-Rays internal storage
            cloned_mop = ida_hexrays.mop_t()
            cloned_mop.make_number(const_val, const_size)
            const_leaf.mop = cloned_mop
            const_leaf.dest_size = const_size

            new_index = len(context.unique_asts)
            const_leaf.ast_index = new_index
            context.unique_asts.append(const_leaf)
            context.mop_key_to_index[key] = new_index
            return const_leaf

    # Fallback for any unhandled mop: treat as a leaf.
    # This is for simple operands (registers, stack vars) or complex
    # instructions that are not part of our MBA analysis.
    if (
        mop.t != ida_hexrays.mop_d
        or (mop.d.opcode not in MBA_RELATED_OPCODES)
        or mop.d.l is None
        or mop.d.r is None
    ):
        tree: AstBase | None
        if mop.t == ida_hexrays.mop_n:
            const_val = int(mop.nnn.value)
            const_size = mop.size
            tree = AstConstant(hex(const_val), const_val, const_size)
            # Re-use a shared constant mop_t from the global cache to avoid the
            # overhead of allocating a fresh object for every identical literal.
            tree.mop = get_constant_mop(const_val, const_size)
            tree.dest_size = const_size  # detached copy
        # Typed-immediate wrappers (mop_f) are now normalised by the
        # TypedImmediateCanonicaliseRule peephole pass.  If we still see one
        # here it means it holds *no* literal value, therefore fall through to
        # generic leaf creation.
        elif mop.t == ida_hexrays.mop_f:
            tree = None
        else:
            tree = None

        # ------------------------------------------------------------------
        # If we still haven't built a node, create a generic AstLeaf now.  This
        # guarantees that *tree* is always defined even if new mop_t kinds are
        # introduced in future IDA versions.
        # ------------------------------------------------------------------
        if tree is None:
            tree = AstLeaf(format_mop_t(mop))
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Tree is NONE! Defaulting to AstLeaf for mop type %s dstr=%s",
                    mop_type_to_string(mop.t),
                    str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
                )
            tree.dest_size = mop.size

        # For non-constant leaves we deliberately *do not* keep a reference
        # to the original mop_t object, because Hex-Rays may free or reuse
        # it after micro-optimisations, leading to use-after-free crashes.
        # Only constant leaves benefit from holding the numeric mop to
        # speed up further evaluations.
        if tree.is_constant():
            tree.mop = getattr(tree, "mop", None) or mop
        else:
            tree = AstLeaf(format_mop_t(mop))
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Fallback to AstLeaf for mop type %s dstr=%s",
                    mop_type_to_string(mop.t),
                    str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
                )
            tree.dest_size = mop.size

        # Preserve previously assigned mop (e.g., inner numeric mop) unless
        # it is still unset.  This prevents clobbering the constant `mop_n`
        # we stored above with the wrapper operand, which would break
        # constant detection later in the pipeline.
        if getattr(tree, "mop", None) is None:
            tree.mop = mop
        dest_size = (
            mop.size
            if mop.t != ida_hexrays.mop_d
            else mop.d.d.size if mop.d.d is not None else mop.size
        )
        tree.dest_size = dest_size
        new_index = len(context.unique_asts)
        tree.ast_index = new_index
        context.unique_asts.append(tree)
        context.mop_key_to_index[key] = new_index
        return tree

    # If we reach here, we failed to build an AST. Log the full mop tree.
    logger.error("[mop_to_ast_internal] Could not build AST for mop. Dumping mop tree:")
    mop_tree(mop)
    return None



# # Port mop_to_ast_internal as a cdef function
# # Use 'object' for mop initially for compatibility with SWIG wrapper
# cdef object mop_to_ast_internal_cy(object mop, AstBuilderContext bldr_ctx, object ctx, bint root=False):
#     # Use project-specific debug flag
#     if root and logger.debug_on:
#         logger.debug(
#             "[mop_to_ast_internal] Processing root mop: %s",
#             str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
#         )

#     # Early filter at root - MATCH PYTHON VERSION EXACTLY
#     if root:
#         if hasattr(mop, "d") and hasattr(mop.d, "opcode"):
#             root_opcode = mop.d.opcode

#             # Check against MBA_RELATED_OPCODES and rotate helpers
#             if root_opcode not in MBA_RELATED_OPCODES and not is_rotate_helper_call(mop.d):
#                 if logger.debug_on:
#                     logger.debug(
#                         "Skipping AST build for unsupported root opcode: %s",
#                         opcode_to_string(root_opcode),
#                     )
#                 return None

#     # 1. Create the unique, hashable key for the current mop.
#     key = get_mop_key_cy(mop)

#     # 2. Thread-local deduplication
#     if key in bldr_ctx.mop_key_to_index:
#         existing_index = bldr_ctx.mop_key_to_index[key]
#         return bldr_ctx.unique_asts[existing_index]

#     # NEW: Build AST nodes for MBA-related opcodes
#     # In the MBA_RELATED_OPCODES section:
#     if (mop.t == ida_hexrays.mop_d and
#         mop.d is not None and  # Add this check
#         hasattr(mop.d, 'opcode') and  # Add this check
#         mop.d.opcode in MBA_RELATED_OPCODES):

#         # Additional safety checks
#         if mop.d.l is None:
#             if logger.debug_on:
#                 logger.debug("[mop_to_ast_internal] Missing left operand for opcode %s",
#                             opcode_to_string(mop.d.opcode))
#         nb_ops = OPCODES_INFO[mop.d.opcode]["nb_operands"]
#         # Gather children ASTs based on operand count
#         # Recursive calls to the Cython version
#         left_ast = mop_to_ast_internal_cy(mop.d.l, bldr_ctx, ctx) if mop.d.l is not None else None
#         right_ast = (
#             mop_to_ast_internal_cy(mop.d.r, bldr_ctx, ctx)
#             if (nb_ops >= 2 and mop.d.r is not None)
#             else None
#         )

#         # Require at least the mandatory operands
#         if left_ast is None:
#             # Can't build meaningful node - fallback later to leaf
#             if logger.debug_on:
#                 logger.debug(
#                     "[mop_to_ast_internal] Missing mandatory operand(s) for opcode %s, will treat as leaf",
#                     opcode_to_string(mop.d.opcode),
#                 )
#         else:
#             # Only use dst_ast if destination present
#             dst_ast = mop_to_ast_internal_cy(mop.d.d, bldr_ctx, ctx) if mop.d.d is not None else None

#             # Create AstNode (Python object)
#             tree = AstNode(mop.d.opcode, left_ast, right_ast, dst_ast)

#             # Set dest_size robustly
#             if hasattr(mop, "size") and mop.size:
#                 tree.dest_size = mop.size
#             elif hasattr(mop.d, "size") and mop.d.size:
#                 tree.dest_size = mop.d.size
#             elif mop.d.l is not None and hasattr(mop.d.l, "size"):
#                 tree.dest_size = mop.d.l.size
#             else:
#                 tree.dest_size = None

#             tree.mop = mop
#             tree.ea = sanitize_ea(mop.d.ea)

#             if logger.debug_on:
#                 logger.debug(
#                     "[mop_to_ast_internal] Created AstNode for opcode %s (ea=0x%X): %s",
#                     opcode_to_string(mop.d.opcode),
#                     mop.d.ea if hasattr(mop.d, "ea") else -1,
#                     tree,
#                 )

#             new_index = len(bldr_ctx.unique_asts)
#             tree.ast_index = new_index
#             bldr_ctx.unique_asts.append(tree)
#             bldr_ctx.mop_key_to_index[key] = new_index
#             return tree

#     # Special handling for mop_d that wraps an m_ldc as a constant leaf
#     if (
#         mop.t == ida_hexrays.mop_d
#         and mop.d is not None
#         and mop.d.opcode == ida_hexrays.m_ldc
#     ):
#         ldc_src = mop.d.l
#         if ldc_src is not None and ldc_src.t == ida_hexrays.mop_n:
#             const_val = int(ldc_src.nnn.value)
#             const_size = ldc_src.size
#             const_leaf = AstConstant(hex(const_val), const_val, const_size)

#             # Use get_constant_mop (Python function) - Reuse shared mop
#             const_leaf.mop = ctx["get_constant_mop_py"](const_val, const_size)
#             const_leaf.dest_size = const_size

#             new_index = len(bldr_ctx.unique_asts)
#             const_leaf.ast_index = new_index
#             bldr_ctx.unique_asts.append(const_leaf)
#             bldr_ctx.mop_key_to_index[key] = new_index
#             return const_leaf

#     # Fallback for any unhandled mop: treat as a leaf.
#     tree = None
#     if mop.t == ida_hexrays.mop_n:
#         const_val = int(mop.nnn.value)
#         const_size = mop.size
#         tree = AstConstant(hex(const_val), const_val, const_size)
#         # Re-use a shared constant mop_t
#         tree.mop = ctx["get_constant_mop_py"](const_val, const_size)
#         tree.dest_size = const_size

#     elif mop.t == ida_hexrays.mop_f:
#         tree = None
#     else:
#         tree = None

#     # ------------------------------------------------------------------
#     # If we still haven't built a node, create a generic AstLeaf now.
#     # ------------------------------------------------------------------
#     if tree is None:
#         tree = AstLeaf(format_mop_t(mop))
#         if logger.debug_on:
#             logger.debug(
#                 "[mop_to_ast_internal] Tree is NONE! Defaulting to AstLeaf for mop type %s dstr=%s",
#                 mop_type_to_string(mop.t),
#                 str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
#             )
#         tree.dest_size = mop.size

#     # For non-constant leaves, create a new AstLeaf (as per original logic)
#     # Note: The original Python logic seems to have a duplicate/overwriting section here.
#     # The ported version reflects the final outcome of that logic.
#     if not tree.is_constant():
#         tree = AstLeaf(format_mop_t(mop)) # Overwrite with generic leaf
#         if logger.debug_on:
#             logger.debug(
#                 "[mop_to_ast_internal] Fallback to AstLeaf for mop type %s dstr=%s",
#                 mop_type_to_string(mop.t),
#                 str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
#             )
#         tree.dest_size = mop.size

#     # Preserve previously assigned mop for constants, assign mop for others
#     if getattr(tree, "mop", None) is None:
#         tree.mop = mop

#     # Determine dest_size (mirroring original logic's attempt)
#     dest_size = (
#         mop.size
#         if mop.t != ida_hexrays.mop_d
#         else (mop.d.d.size if mop.d.d is not None else mop.size)
#     )
#     tree.dest_size = dest_size

#     new_index = len(bldr_ctx.unique_asts)
#     tree.ast_index = new_index
#     bldr_ctx.unique_asts.append(tree)
#     bldr_ctx.mop_key_to_index[key] = new_index
#     return tree

#     # If we reach here, we failed to build an AST.
#     # logger.error("[mop_to_ast_internal] Could not build AST for mop. Dumping mop tree (not implemented in Cython port yet)")
#     # mop_tree(mop) # Assuming mop_tree is a Python function, might need special handling or commenting out for now
#     # return None # Implicit return None at end of function


def mop_to_ast(mop: ida_hexrays.mop_t) -> AstProxy | None:
    """
    Converts a mop_t to an AST node, with caching to avoid re-computation.

    Returns a deep copy of the cached AST to prevent side-effects from
    mutations by the caller.
    """

    # 1. Create a stable, hashable key from the mop_t object.
    cache_key = get_mop_key(mop)

    # 2. Global template cache: return a proxy if we already know the template
    if cache_key in MOP_TO_AST_CACHE:
        cached_template = MOP_TO_AST_CACHE[cache_key]
        if cached_template is None:
            return None  # Previously determined unconvertible.
        return AstProxy(cached_template)

    builder_context = AstBuilderContext()
    # Start the optimized recursive build.

    if not (mop_ast := mop_to_ast_internal(mop, builder_context, root=True)):
        # Cache the failure to avoid re-computing it.
        MOP_TO_AST_CACHE[cache_key] = None
        return None

    # This mutates the mop_ast object, populating its sub_ast_info.
    # We do this ONCE before caching the "template" object, then we
    # freeze the object to prevent mutations.
    mop_ast.compute_sub_ast()
    mop_ast.freeze()

    # 4. Store the newly computed "template" object in the cache.
    MOP_TO_AST_CACHE[cache_key] = mop_ast

    # 5. Return a proxy to the caller for safety.
    return AstProxy(mop_ast)



# # Port mop_to_ast as a cdef function
# cdef object mop_to_ast_cy(object mop, object ctx):
#     """
#     Converts a mop_t to an AST node, with caching to avoid re-computation.
#     Returns a deep copy of the cached AST to prevent side-effects from
#     mutations by the caller.
#     """
#     # 1. Create a stable, hashable key from the mop_t object.
#     # Call the Python get_mop_key function
#     cache_key = get_mop_key_cy(mop)

#     # 2. Global template cache: return a proxy if we already know the template
#     # Access the global Python MOP_TO_AST_CACHE dict
#     if cache_key in ctx["mop_to_ast_cache_py"]:
#         cached_template = ctx["mop_to_ast_cache_py"][cache_key]
#         if cached_template is None:
#             return None  # Previously determined unconvertible.
#         # Return ctx["ast_proxy_py"] (Python object)
#         return ctx["ast_proxy_py"](cached_template)

#     # Create builder context
#     builder_context = AstBuilderContext()

#     # Start the optimized recursive build.
#     # Call the Cython version
#     mop_ast = mop_to_ast_internal_cy(mop, builder_context, ctx, root=True)
#     if not mop_ast:
#         # Cache the failure to avoid re-computing it.
#         ctx["mop_to_ast_cache_py"][cache_key] = None
#         return None

#     # This mutates the mop_ast object, populating its sub_ast_info.
#     mop_ast.compute_sub_ast()
#     mop_ast.freeze()

#     # 4. Store the newly computed "template" object in the cache.
#     ctx["mop_to_ast_cache_py"][cache_key] = mop_ast

#     # 5. Return a proxy to the caller for safety.
#     return ctx["ast_proxy_py"](mop_ast)


def minsn_to_ast(instruction: ida_hexrays.minsn_t) -> AstProxy | None:
    try:
        # Early filter: forbidden opcodes
        if instruction.opcode in MINSN_TO_AST_FORBIDDEN_OPCODES:
            if logger.debug_on:
                logger.debug(
                    "Skipping AST build for forbidden opcode: %s @ 0x%x %s",
                    opcode_to_string(instruction.opcode),
                    instruction.ea,
                    (
                        "({0})".format(instruction.dstr())
                        if instruction.opcode != ida_hexrays.m_jtbl
                        else ""
                    ),
                )
            return None

        # Early filter: unsupported opcodes (not in MBA_RELATED_OPCODES)
        # Allow rotate helper calls ("__ROL*" / "__ROR*") even though m_call
        # is normally filtered out - they can be constant-folded later.
        if instruction.opcode not in MBA_RELATED_OPCODES and not is_rotate_helper_call(
            instruction
        ):
            if logger.debug_on:
                logger.debug(
                    "Skipping AST build for unsupported opcode: %s @ 0x%x %s",
                    opcode_to_string(instruction.opcode),
                    instruction.ea,
                    (
                        "({0})".format(instruction.dstr())
                        if instruction.opcode != ida_hexrays.m_jtbl
                        else ""
                    ),
                )
            return None

        # Constant-returning helper calls are folded to m_ldc by the peephole
        # pass ConstantCallResultFoldRule.  No need for AST special case.

        # Transparent-call shortcut: no args, computation stored in destination mop_d
        if (
            instruction.opcode == ida_hexrays.m_call
            and (instruction.r is None or instruction.r.t == ida_hexrays.mop_z)
            and instruction.d is not None
            and instruction.d.t == ida_hexrays.mop_d
        ):
            if logger.debug_on:
                logger.debug(
                    "[minsn_to_ast] Unwrapping call with empty args; using destination expression for AST",
                )
            dest_ast = mop_to_ast(instruction.d)
            if dest_ast is not None:
                return dest_ast

        ins_mop = ida_hexrays.mop_t()
        ins_mop.create_from_insn(instruction)

        # if instruction.opcode == ida_hexrays.m_mov:
        #     tmp = AstNode(ida_hexrays.m_mov, mop_to_ast(ins_mop))
        #     tmp.mop = ins_mop
        #     tmp.dest_size = instruction.d.size
        #     tmp.ea = instruction.ea
        #     tmp.dst_mop = instruction.d
        #     return tmp

        tmp = mop_to_ast(ins_mop)
        if tmp is None:
            if logger.debug_on:
                logger.debug(
                    "Skipping AST build for unsupported or nop instruction: %s @ 0x%x %s",
                    opcode_to_string(instruction.opcode),
                    instruction.ea,
                    (
                        "({0})".format(instruction.dstr())
                        if instruction.opcode != ida_hexrays.m_jtbl
                        else ""
                    ),
                )
        else:
            tmp.dst_mop = instruction.d
        return tmp
    except RuntimeError as e:
        logger.error(
            "Error while transforming instruction %s: %s",
            format_minsn_t(instruction),
            e,
        )



# def minsn_to_ast_cy(
#     object ins_py,
#     object mop_to_ast_cache_py,
#     object ast_proxy_py,
#     object ast_node_py,
#     object ast_leaf_py,
#     object ast_constant_py,
#     object get_constant_mop_py,
#     object mba_related_opcodes_py,
# ):
#     """
#     Public entry point matching the signature expected by the original ast.py fast path.
#     """
#     cdef:
#         object ins_mop
#         object dest_ast
#         object result
#     try:
#         # Early filter: forbidden opcodes
#         if ins_py.opcode in MINSN_TO_AST_FORBIDDEN_OPCODES:
#             if logger.debug_on:
#                 logger.debug(
#                     "Skipping AST build for forbidden opcode: %s @ 0x%x",
#                     opcode_to_string(ins_py.opcode),
#                     ins_py.ea,
#                 )
#             return None

#         # Early filter: unsupported opcodes (not in MBA_RELATED_OPCODES)
#         # Allow rotate helper calls ("__ROL*" / "__ROR*")
#         if ins_py.opcode not in MBA_RELATED_OPCODES and not is_rotate_helper_call(ins_py):
#             if logger.debug_on:
#                 logger.debug(
#                     "Skipping AST build for unsupported opcode: %s @ 0x%x",
#                     opcode_to_string(ins_py.opcode),
#                     ins_py.ea,
#                 )
#             return None

#         # Transparent-call shortcut: no args, computation stored in destination mop_d
#         if (
#             ins_py.opcode == ida_hexrays.m_call
#             and (ins_py.r is None or ins_py.r.t == ida_hexrays.mop_z)
#             and ins_py.d is not None
#             and ins_py.d.t == ida_hexrays.mop_d
#         ):
#             if logger.debug_on:
#                 logger.debug(
#                     "[minsn_to_ast] Unwrapping call with empty args; using destination expression for AST",
#                 )
#             # For this case, we need to process the destination mop
#             ins_mop = ida_hexrays.mop_t()
#             ins_mop.create_from_insn(ins_py)

#             kwargs = {
#                 "mop_to_ast_cache_py": mop_to_ast_cache_py,
#                 "ast_proxy_py": ast_proxy_py,
#                 "ast_node_py": ast_node_py,
#                 "ast_leaf_py": ast_leaf_py,
#                 "ast_constant_py": ast_constant_py,
#                 "get_constant_mop_py": get_constant_mop_py,
#                 "mba_related_opcodes_py": mba_related_opcodes_py,
#             }

#             dest_ast = mop_to_ast_cy(ins_py.d, kwargs)
#             return dest_ast

#         # Create mop from instruction
#         ins_mop = ida_hexrays.mop_t()
#         ins_mop.create_from_insn(ins_py)

#         kwargs = {
#             "mop_to_ast_cache_py": mop_to_ast_cache_py,
#             "ast_proxy_py": ast_proxy_py,
#             "ast_node_py": ast_node_py,
#             "ast_leaf_py": ast_leaf_py,
#             "ast_constant_py": ast_constant_py,
#             "get_constant_mop_py": get_constant_mop_py,
#             "mba_related_opcodes_py": mba_related_opcodes_py,
#         }

#         result = mop_to_ast_cy(ins_mop, kwargs)

#         # Set dst_mop if result exists (to match Python behavior)
#         if result is not None:
#             result.dst_mop = ins_py.d

#         return result

#     except RuntimeError as e:
#         logger.error(
#             "Error while transforming instruction %s: %s",
#             str(ins_py.dstr()) if hasattr(ins_py, "dstr") else str(ins_py),
#             e,
#             exc_info=True,
#         )
#         raise
#     except Exception as e:
#         logger.error(
#             "Unexpected error while transforming instruction %s: %s",
#             str(ins_py.dstr()) if hasattr(ins_py, "dstr") else str(ins_py),
#             e,
#             exc_info=True,
#         )
#         raise
