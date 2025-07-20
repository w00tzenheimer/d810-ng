from __future__ import annotations

import abc
import logging
import typing
from typing import Dict, List, Tuple, Union

import ida_hexrays
import idaapi

from d810.errors import AstEvaluationException
from d810.expr.utils import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
    get_add_cf,
    get_add_of,
    get_parity_flag,
    get_sub_of,
    signed_to_unsigned,
    unsigned_to_signed,
)
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
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
)

logger = logging.getLogger("D810")


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


def clear_mop_to_ast_cache():
    """
    Call this when the analysis context changes (e.g., new function)
    to prevent using stale data.
    """
    MOP_TO_AST_CACHE.clear()


class AstInfo(object):
    def __init__(self, ast: AstNode | AstLeaf, number_of_use: int):
        self.ast = ast
        self.number_of_use = number_of_use

    def __str__(self):
        return f"{self.ast} used {self.number_of_use} times: {format_mop_t(self.ast.mop) if self.ast.mop else 0}"


class AstBase(abc.ABC):

    sub_ast_info_by_index: Dict[int, AstInfo] = {}
    mop: ida_hexrays.mop_t | None = None
    dest_size: int | None = None
    ea: int | None = None
    ast_index: int | None = None

    @property
    @abc.abstractmethod
    def is_frozen(self) -> bool: ...

    @abc.abstractmethod
    def clone(self) -> AstBase: ...

    @abc.abstractmethod
    def freeze(self) -> None: ...

    @abc.abstractmethod
    def is_node(self) -> bool: ...

    @abc.abstractmethod
    def is_leaf(self) -> bool: ...

    @abc.abstractmethod
    def is_constant(self) -> bool: ...

    @abc.abstractmethod
    def compute_sub_ast(self) -> None: ...

    @abc.abstractmethod
    def get_leaf_list(self) -> List[AstLeaf]: ...

    @abc.abstractmethod
    def reset_mops(self) -> None: ...

    @abc.abstractmethod
    def _copy_mops_from_ast(self, other: AstBase) -> bool: ...

    @abc.abstractmethod
    def create_mop(self, ea: int) -> ida_hexrays.mop_t: ...

    @abc.abstractmethod
    def get_pattern(self) -> str: ...

    @abc.abstractmethod
    def evaluate(self, dict_index_to_value: Dict[int, int]) -> int: ...

    @abc.abstractmethod
    def get_depth_signature(self, depth: int) -> List[str]: ...


class AstNode(AstBase, dict):
    def __init__(
        self,
        opcode: int,
        left: AstBase | None = None,
        right: AstBase | None = None,
        dst: AstBase | None = None,
    ):
        super().__init__()
        self.opcode = opcode
        self.left = left
        self.right = right
        self.dst = dst
        self.dst_mop = None

        self.opcodes = []
        self.mop = None
        self.is_candidate_ok = False

        self.leafs = []
        self.leafs_by_name = {}

        self.ast_index = 0
        self.sub_ast_info_by_index = {}

        self.dest_size = None
        self.ea = None
        self.func_name: str = ""
        self._is_frozen = False  # All newly created nodes are mutable by default

    @property
    @typing.override
    def is_frozen(self) -> bool:
        return self._is_frozen

    @typing.override
    def freeze(self):
        """Recursively freezes this node and all its children."""
        if self._is_frozen:
            return
        self._is_frozen = True
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

    def get_leaf_list(self) -> List[AstLeaf]:
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

    def check_pattern_and_copy_mops(self, ast: Union[AstNode, AstLeaf]) -> bool:
        self.reset_mops()
        is_matching_shape = self._copy_mops_from_ast(ast)
        if not is_matching_shape:
            return False
        return self._check_implicit_equalities()

    def reset_mops(self):
        self.mop = None
        if self.left is not None:
            self.left.reset_mops()
        if self.right is not None:
            self.right.reset_mops()

    def _copy_mops_from_ast(self, other: AstNode | AstLeaf) -> bool:
        self.mop = other.mop
        self.dst_mop = other.dst_mop
        self.dest_size = other.dest_size
        self.ea = other.ea

        if not other.is_node():
            return False
        other = typing.cast(AstNode, other)
        if self.opcode != other.opcode:
            return False
        if self.left is not None and other.left is not None:
            if not self.left._copy_mops_from_ast(other.left):
                return False
        if self.right is not None and other.right is not None:
            if not self.right._copy_mops_from_ast(other.right):
                return False
        return True

    def _check_implicit_equalities(self) -> bool:
        self.leafs = self.get_leaf_list()
        self.leafs_by_name = {}
        self.is_candidate_ok = True

        for leaf in self.leafs:
            ref_leaf = self.leafs_by_name.get(leaf.name)
            if ref_leaf is not None and leaf.mop is not None:
                if not equal_mops_ignore_size(ref_leaf.mop, leaf.mop):
                    self.is_candidate_ok = False
            self.leafs_by_name[leaf.name] = leaf
        return self.is_candidate_ok

    def update_leafs_mop(
        self,
        other: AstNode,
        other2: AstNode | None = None,
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

    def evaluate_with_leaf_info(self, leafs_info, leafs_value):
        dict_index_to_value = {
            leaf_info.ast.ast_index: leaf_value
            for leaf_info, leaf_value in zip(leafs_info, leafs_value)
        }
        res = self.evaluate(dict_index_to_value)
        return res

    def evaluate(self, dict_index_to_value: Dict[int, int]) -> int:
        if self.ast_index in dict_index_to_value:
            return dict_index_to_value[self.ast_index]
        if self.dest_size is None:
            raise ValueError("dest_size is None")

        res_mask = AND_TABLE[self.dest_size]

        if self.left is None:
            raise ValueError(f"left is None for opcode: {self.opcode}")

        binary_opcodes = {
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_mul,
            ida_hexrays.m_udiv,
            ida_hexrays.m_sdiv,
            ida_hexrays.m_umod,
            ida_hexrays.m_smod,
            ida_hexrays.m_or,
            ida_hexrays.m_and,
            ida_hexrays.m_xor,
            ida_hexrays.m_shl,
            ida_hexrays.m_shr,
            ida_hexrays.m_sar,
            ida_hexrays.m_cfadd,
            ida_hexrays.m_ofadd,
            ida_hexrays.m_seto,
            ida_hexrays.m_setnz,
            ida_hexrays.m_setz,
            ida_hexrays.m_setae,
            ida_hexrays.m_setb,
            ida_hexrays.m_seta,
            ida_hexrays.m_setbe,
            ida_hexrays.m_setg,
            ida_hexrays.m_setge,
            ida_hexrays.m_setl,
            ida_hexrays.m_setle,
            ida_hexrays.m_setp,
        }

        if self.opcode in binary_opcodes and self.right is None:
            raise ValueError("right is None for binary opcode: {0}".format(self.opcode))

        match self.opcode:
            case ida_hexrays.m_mov:
                return (self.left.evaluate(dict_index_to_value)) & res_mask
            case ida_hexrays.m_neg:
                return (-self.left.evaluate(dict_index_to_value)) & res_mask
            case ida_hexrays.m_lnot:
                return self.left.evaluate(dict_index_to_value) != 0
            case ida_hexrays.m_bnot:
                return (self.left.evaluate(dict_index_to_value) ^ res_mask) & res_mask
            case ida_hexrays.m_xds:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                return signed_to_unsigned(left_value_signed, self.dest_size) & res_mask
            case ida_hexrays.m_xdu:
                return (self.left.evaluate(dict_index_to_value)) & res_mask
            case ida_hexrays.m_low:
                return (self.left.evaluate(dict_index_to_value)) & res_mask
            case ida_hexrays.m_add if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    + self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_sub if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    - self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_mul if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    * self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_udiv if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    // self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_sdiv if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    // self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_umod if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    % self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_smod if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    % self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_or if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    | self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_and if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    & self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_xor if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    ^ self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_shl if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    << self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_shr if self.right is not None:
                return (
                    self.left.evaluate(dict_index_to_value)
                    >> self.right.evaluate(dict_index_to_value)
                ) & res_mask
            case ida_hexrays.m_sar if self.right is not None:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                res_signed = left_value_signed >> self.right.evaluate(
                    dict_index_to_value
                )
                return signed_to_unsigned(res_signed, self.dest_size) & res_mask
            case ida_hexrays.m_cfadd if self.right is not None:
                tmp = get_add_cf(
                    self.left.evaluate(dict_index_to_value),
                    self.right.evaluate(dict_index_to_value),
                    self.left.dest_size,
                )
                return tmp & res_mask
            case ida_hexrays.m_ofadd if self.right is not None:
                tmp = get_add_of(
                    self.left.evaluate(dict_index_to_value),
                    self.right.evaluate(dict_index_to_value),
                    self.left.dest_size,
                )
                return tmp & res_mask
            case ida_hexrays.m_sets:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                res = 1 if left_value_signed < 0 else 0
                return res & res_mask
            case ida_hexrays.m_seto if self.right is not None:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    self.right.evaluate(dict_index_to_value), self.right.dest_size
                )
                sub_overflow = get_sub_of(
                    left_value_signed, right_value_signed, self.left.dest_size
                )
                return sub_overflow & res_mask
            case ida_hexrays.m_setnz if self.right is not None:
                res = (
                    1
                    if self.left.evaluate(dict_index_to_value)
                    != self.right.evaluate(dict_index_to_value)
                    else 0
                )
                return res & res_mask
            case ida_hexrays.m_setz if self.right is not None:
                res = (
                    1
                    if self.left.evaluate(dict_index_to_value)
                    == self.right.evaluate(dict_index_to_value)
                    else 0
                )
                return res & res_mask
            case ida_hexrays.m_setae if self.right is not None:
                res = (
                    1
                    if self.left.evaluate(dict_index_to_value)
                    >= self.right.evaluate(dict_index_to_value)
                    else 0
                )
                return res & res_mask
            case ida_hexrays.m_setb if self.right is not None:
                res = (
                    1
                    if self.left.evaluate(dict_index_to_value)
                    < self.right.evaluate(dict_index_to_value)
                    else 0
                )
                return res & res_mask
            case ida_hexrays.m_seta if self.right is not None:
                res = (
                    1
                    if self.left.evaluate(dict_index_to_value)
                    > self.right.evaluate(dict_index_to_value)
                    else 0
                )
                return res & res_mask
            case ida_hexrays.m_setbe if self.right is not None:
                res = (
                    1
                    if self.left.evaluate(dict_index_to_value)
                    <= self.right.evaluate(dict_index_to_value)
                    else 0
                )
                return res & res_mask
            case ida_hexrays.m_setg if self.right is not None:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    self.right.evaluate(dict_index_to_value), self.right.dest_size
                )
                res = 1 if left_value_signed > right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setge if self.right is not None:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    self.right.evaluate(dict_index_to_value), self.right.dest_size
                )
                res = 1 if left_value_signed >= right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setl if self.right is not None:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    self.right.evaluate(dict_index_to_value), self.right.dest_size
                )
                res = 1 if left_value_signed < right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setle if self.right is not None:
                left_value_signed = unsigned_to_signed(
                    self.left.evaluate(dict_index_to_value), self.left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    self.right.evaluate(dict_index_to_value), self.right.dest_size
                )
                res = 1 if left_value_signed <= right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setp if self.right is not None:
                res = get_parity_flag(
                    self.left.evaluate(dict_index_to_value),
                    self.right.evaluate(dict_index_to_value),
                    self.left.dest_size,
                )
                return res & res_mask
            case _:
                raise AstEvaluationException(
                    "Can't evaluate opcode: {0}".format(self.opcode)
                )

    def get_depth_signature(self, depth):
        if depth == 1:
            return ["{0}".format(self.opcode)]
        tmp = []
        nb_operands = OPCODES_INFO[self.opcode]["nb_operands"]
        if (nb_operands >= 1) and self.left is not None:
            tmp += self.left.get_depth_signature(depth - 1)
        else:
            tmp += ["N"] * (2 ** (depth - 2))
        if (nb_operands >= 2) and self.right is not None:
            tmp += self.right.get_depth_signature(depth - 1)
        else:
            tmp += ["N"] * (2 ** (depth - 2))
        return tmp

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

    @typing.override
    def clone(self):
        # Use __new__ to bypass __init__ for speed
        new_node = self.__class__.__new__(self.__class__)
        super(AstNode, new_node).__init__()  # Initialize the dict part

        # Manually copy attributes and clone children
        new_node.opcode = self.opcode
        new_node.left = self.left.clone() if self.left else None
        new_node.right = self.right.clone() if self.right else None
        new_node.dst = self.dst.clone() if self.dst else None

        new_node.mop = self.mop
        new_node.dst_mop = self.dst_mop
        new_node.dest_size = self.dest_size
        new_node.ea = self.ea
        new_node.ast_index = self.ast_index

        # Initialize transient state
        new_node.is_candidate_ok = False
        new_node.leafs = []
        new_node.leafs_by_name = {}
        new_node.opcodes = []
        new_node.sub_ast_info_by_index = {}  # Start fresh

        # Cloned objects start mutable
        new_node._is_frozen = False

        return new_node

    @typing.override
    def is_node(self):
        return True

    @typing.override
    def is_leaf(self):
        # An AstNode is not a leaf, so returns False
        return False

    @typing.override
    def is_constant(self):
        return False


class AstLeaf(AstBase):
    def __init__(self, name):
        self.name = name
        self.ast_index: int | None = None

        self.mop = None
        self.z3_var = None
        self.z3_var_name = None

        self.dest_size = None
        self.ea = None
        self._is_frozen = False  # All newly created nodes are mutable by default
        self.sub_ast_info_by_index = {}

    @property
    @typing.override
    def is_frozen(self) -> bool:
        return self._is_frozen

    @typing.override
    def freeze(self):
        """Recursively freezes this node and all its children."""
        if self._is_frozen:
            return
        self._is_frozen = True

    @typing.override
    def is_node(self):
        return False

    @typing.override
    def is_leaf(self):
        return True

    @typing.override
    def is_constant(self):
        if self.mop is None:
            return False
        return self.mop.t == ida_hexrays.mop_n

    @typing.override
    def clone(self):
        # Use __new__ to bypass __init__ for speed
        new_leaf = self.__class__.__new__(self.__class__)

        # Manually copy attributes. This is faster than generic deepcopy.
        new_leaf.name = self.name
        new_leaf.ast_index = self.ast_index
        new_leaf.mop = self.mop
        new_leaf.dest_size = self.dest_size
        new_leaf.ea = self.ea

        # Initialize transient state
        new_leaf.z3_var = None
        new_leaf.z3_var_name = None
        new_leaf.sub_ast_info_by_index = {}  # Start fresh

        # Cloned objects start mutable by definition
        new_leaf._is_frozen = False

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
        # Currently, we are not creating a new mop but returning the one defined
        return self.mop

    def update_leafs_mop(self, other: AstNode, other2: AstNode | None = None):
        if other is not None and self.name in other.leafs_by_name:
            self.mop = other.leafs_by_name[self.name].mop
            return True
        elif other2 is not None and self.name in other2.leafs_by_name:
            self.mop = other2.leafs_by_name[self.name].mop
            return True
        return False

    def check_pattern_and_copy_mops(self, ast):
        self.reset_mops()
        is_matching_shape = self._copy_mops_from_ast(ast)

        if not is_matching_shape:
            return False
        return self._check_implicit_equalities()

    def reset_mops(self):
        self.z3_var = None
        self.z3_var_name = None
        self.mop = None

    def _copy_mops_from_ast(self, other):
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
        dict_index_to_value = {
            leaf_info.ast.ast_index: leaf_value
            for leaf_info, leaf_value in zip(leafs_info, leafs_value)
        }
        res = self.evaluate(dict_index_to_value)
        return res

    def evaluate(self, dict_index_to_value):
        if self.is_constant() and self.mop is not None:
            return self.mop.nnn.value
        assert self.ast_index is not None
        return dict_index_to_value.get(self.ast_index)

    def get_depth_signature(self, depth):
        if depth == 1:
            if self.is_constant():
                return ["C"]
            return ["L"]
        else:
            return ["N"] * (2 ** (depth - 1))

    @typing.override
    def __str__(self):
        try:
            if self.is_constant() and self.mop is not None:
                return "{0}".format(hex(self.mop.nnn.value))
            if self.z3_var_name is not None:
                return self.z3_var_name
            if self.ast_index is not None:
                return "x_{0}".format(self.ast_index)
            if self.mop is not None:
                return format_mop_t(self.mop)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstLeaf: {0}".format(e))
            return "Error_AstLeaf"


class AstConstant(AstLeaf):
    def __init__(self, name, expected_value=None, expected_size=None):
        super().__init__(name)
        self.expected_value = expected_value
        self.expected_size = expected_size

    @property
    def value(self):
        assert self.mop is not None and self.mop.t == ida_hexrays.mop_n
        return self.mop.nnn.value

    @typing.override
    def is_constant(self) -> bool:
        # An AstConstant is always constant, so return True
        return True

    def _copy_mops_from_ast(self, other):
        if other.mop is not None and other.mop.t != ida_hexrays.mop_n:
            return False

        self.mop = other.mop
        if self.expected_value is None:
            return True
        return self.expected_value == other.mop.nnn.value

    def evaluate(self, dict_index_to_value=None):
        if self.mop is not None and self.mop.t == ida_hexrays.mop_n:
            return self.mop.nnn.value
        return self.expected_value

    def get_depth_signature(self, depth):
        if depth == 1:
            return ["C"]
        else:
            return ["N"] * (2 ** (depth - 1))

    @typing.override
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


class AstProxy(AstBase):
    def __init__(self, target_ast: AstBase):
        # The proxy initially holds a reference to the shared, frozen template
        self._target = target_ast

    @property
    @typing.override
    def is_frozen(self) -> bool:
        return self._target.is_frozen

    @typing.override
    def clone(self) -> AstBase:
        return AstProxy(self._target.clone())

    @typing.override
    def freeze(self) -> None:
        self._target.freeze()

    @typing.override
    def is_node(self) -> bool:
        return self._target.is_node()

    @typing.override
    def is_leaf(self) -> bool:
        return self._target.is_leaf()

    @typing.override
    def is_constant(self) -> bool:
        return self._target.is_constant()

    @typing.override
    def compute_sub_ast(self) -> None:
        self._target.compute_sub_ast()

    @typing.override
    def get_leaf_list(self) -> List[AstLeaf]:
        return self._target.get_leaf_list()

    @typing.override
    def reset_mops(self) -> None:
        self._target.reset_mops()

    @typing.override
    def _copy_mops_from_ast(self, other: AstBase) -> bool:
        return self._target._copy_mops_from_ast(other)

    @typing.override
    def create_mop(self, ea: int) -> ida_hexrays.mop_t:
        return self._target.create_mop(ea)

    @typing.override
    def get_pattern(self) -> str:
        return self._target.get_pattern()

    @typing.override
    def evaluate(self, dict_index_to_value: Dict[int, int]) -> int:
        return self._target.evaluate(dict_index_to_value)

    @typing.override
    def get_depth_signature(self, depth: int) -> List[str]:
        return self._target.get_depth_signature(depth)

    @typing.override
    def __str__(self):
        return f"AstProxy({str(self._target)})"

    @typing.override
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

    def _ensure_mutable(self):
        """
        The magic method. If the target is frozen, clone it and
        replace our internal reference with the new, mutable clone.
        """
        if self._target.is_frozen:
            # This is the first write attempt. Time to clone.
            self._target = self._target.clone()  # Assumes clone() exists

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
        if name == "_target":
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
        2) the value obtained from the proxy’s own namespace is *None*.

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

        # If the proxy’s value is a meaningless placeholder (None) but the
        # underlying object has a better value, return the latter instead.
        if val is None:
            target = super().__getattribute__("_target")
            return getattr(target, name)
        return val

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


class AstBuilderContext:
    """
    Manages the state during the recursive construction of an AST.
    This avoids passing multiple related arguments through the recursion
    and provides a clean way to store the lookup dictionary.
    """

    def __init__(self):
        # The list of unique AST nodes. The index in this list is the ast_index.
        self.unique_asts: List[AstBase] = []

        # The fast lookup dictionary.
        # Maps a mop's unique key to its index in the unique_asts list.
        self.mop_key_to_index: Dict[Tuple[int, str], int] = {}


def get_mop_key(mop: ida_hexrays.mop_t) -> tuple:
    """
    Creates a unique, hashable, and cheap-to-compute key for a mop_t object.
    """
    # The base of the key is always the type, size, and valnum.
    t = mop.t
    key_base = (t, mop.size, mop.valnum)

    # Simple Leaf Types
    if t == ida_hexrays.mop_r:  # Register
        return key_base + (mop.r,)
    if t == ida_hexrays.mop_n:  # Number (constant)
        return key_base + (mop.nnn.value,)
    if t == ida_hexrays.mop_v:  # Global variable address
        return key_base + (mop.g,)
    if t == ida_hexrays.mop_S:  # Stack variable
        return key_base + (mop.s.off,)  # Corrected: use .off
    if t == ida_hexrays.mop_l:  # Local variable (lvar)
        return key_base + (mop.l.idx, mop.l.off)
    if t == ida_hexrays.mop_b:  # Block reference
        return key_base + (mop.b,)
    if t == ida_hexrays.mop_h:  # Helper function name
        return key_base + (mop.helper,)
    if t == ida_hexrays.mop_str:  # String literal
        return key_base + (mop.cstr,)

    # Complex Types: Fallback to dstr() for safety and simplicity
    # These types contain pointers to other complex objects, and creating a
    # cheap, unique key without dstr() would require complex recursion.
    if t in (
        ida_hexrays.mop_d,  # Nested instruction
        ida_hexrays.mop_f,  # Function call info
        ida_hexrays.mop_a,  # Address of another operand
        ida_hexrays.mop_p,  # Operand pair
        ida_hexrays.mop_sc,  # Scattered operand
        ida_hexrays.mop_c,  # Switch cases
        ida_hexrays.mop_fn,  # Floating point constant
    ):
        return key_base + (mop.dstr(),)

    # Default case for any other types (e.g., mop_z) Q_Q
    return key_base


def _log_mop_tree(mop, depth=0, max_depth=8):
    indent = "  " * depth
    if mop is None:
        logger.debug("%s<mop=None>", indent)
        return
    try:
        mop_type = mop.t if hasattr(mop, "t") else None
        mop_str = str(mop.dstr()) if hasattr(mop, "dstr") else str(mop)
        logger.debug(
            "%s<mop_t type=%s size=%s valnum=%s dstr=%s>",
            indent,
            mop_type,
            getattr(mop, "size", None),
            getattr(mop, "valnum", None),
            mop_str,
        )
        if depth >= max_depth:
            logger.debug("%s<max depth reached>", indent)
            return
        # Recurse for sub-operands
        if mop_type == ida_hexrays.mop_d and hasattr(mop, "d") and mop.d is not None:
            _log_mop_tree(mop.d.l, depth + 1, max_depth)
            _log_mop_tree(mop.d.r, depth + 1, max_depth)
            _log_mop_tree(mop.d.d, depth + 1, max_depth)
        elif mop_type == ida_hexrays.mop_a and hasattr(mop, "a") and mop.a is not None:
            _log_mop_tree(mop.a, depth + 1, max_depth)
        elif mop_type == ida_hexrays.mop_f and hasattr(mop, "f") and mop.f is not None:
            for arg in getattr(mop.f, "args", []):
                _log_mop_tree(arg, depth + 1, max_depth)
    except Exception as e:
        logger.debug("%s<error logging mop: %s>", indent, e)


def mop_to_ast_internal(
    mop: ida_hexrays.mop_t, context: AstBuilderContext, root: bool = False
) -> AstBase | None:
    # Only log at root
    if root and logger.isEnabledFor(logging.DEBUG):
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

            # Special case: transparent call wrapper
            if (
                root_opcode == ida_hexrays.m_call
                and (mop.d.r is None or mop.d.r.t == ida_hexrays.mop_z)
                and mop.d.d is not None
            ):
                dest_ast = mop_to_ast_internal(mop.d.d, context, root=True)
                if dest_ast is not None:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(
                            "[mop_to_ast_internal] Unwrapped transparent call at 0x%X into dest AST: %s",
                            mop.d.ea if hasattr(mop.d, "ea") else -1,
                            dest_ast,
                        )
                    return dest_ast

            if root_opcode not in MBA_RELATED_OPCODES and not _is_rotate_helper_call(
                mop.d
            ):
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "Skipping AST build for unsupported root opcode: %s",
                        opcode_to_string(root_opcode),
                    )
                return None

    # 1. Create the unique, hashable key for the current mop.
    key = get_mop_key(mop)

    # 2. OPTIMIZATION: Check if this mop has already been processed.
    # This is our O(1) average-time lookup.
    if key in context.mop_key_to_index:
        # It's a hit! We've seen this sub-expression before.
        # Retrieve its index and return the already-created AST object.
        # This prunes the entire recursive branch, saving huge amounts of work.
        existing_index = context.mop_key_to_index[key]
        return context.unique_asts[existing_index]

    # Special handling for rotate calls
    if mop.t == ida_hexrays.mop_d and _is_rotate_helper_call(mop.d):
        # Layout A: classic helper - arguments are in an mop_f list
        if mop.d.r.t == ida_hexrays.mop_f:
            args = mop.d.r.f.args
            if len(args) == 2 and args[0] is not None and args[1] is not None:
                value_ast = mop_to_ast_internal(args[0], context)
                shift_ast = mop_to_ast_internal(args[1], context)
                tree = AstNode(ida_hexrays.m_call, value_ast, shift_ast)
                tree.func_name = mop.d.l.helper
                tree.mop = mop
                tree.dest_size = mop.size
                tree.ea = sanitize_ea(mop.d.ea)
                new_index = len(context.unique_asts)
                tree.ast_index = new_index
                context.unique_asts.append(tree)
                context.mop_key_to_index[key] = new_index
                return tree
        # Layout B: compact helper - r is value, d is shift amount
        elif mop.d.r is not None and mop.d.d is not None:
            value_ast = mop_to_ast_internal(mop.d.r, context)
            shift_ast = mop_to_ast_internal(mop.d.d, context)
            if value_ast is not None and shift_ast is not None:
                tree = AstNode(ida_hexrays.m_call, value_ast, shift_ast)
                tree.func_name = mop.d.l.helper
                tree.mop = mop
                tree.dest_size = mop.size
                tree.ea = sanitize_ea(mop.d.ea)
                new_index = len(context.unique_asts)
                tree.ast_index = new_index
                context.unique_asts.append(tree)
                context.mop_key_to_index[key] = new_index
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "[mop_to_ast_internal] Built compact rotate helper node for ea=0x%X",
                        mop.d.ea if hasattr(mop.d, "ea") else -1,
                    )
                return tree

    # NEW: collapse helper calls that directly yield a constant (dest is constant)
    if mop.t == ida_hexrays.mop_d and mop.d.opcode == ida_hexrays.m_call:
        dest_mop = mop.d.d
        const_mop = None

        if dest_mop is not None:
            # Case A: plain numeric constant
            if dest_mop.t == ida_hexrays.mop_n:
                const_mop = dest_mop

            # Case B: ldc wrapper around a constant
            elif (
                dest_mop.t == ida_hexrays.mop_d
                and dest_mop.d is not None
                and dest_mop.d.opcode == ida_hexrays.m_ldc
                and dest_mop.d.l is not None
                and dest_mop.d.l.t == ida_hexrays.mop_n
            ):
                const_mop = dest_mop.d.l

            # Case C: typed-immediate held in a mop_f wrapper (e.g., <fast:_QWORD #0x42.8,char #4.1>.8)
            elif dest_mop.t == ida_hexrays.mop_f and getattr(dest_mop, "f", None):
                args = dest_mop.f.args
                if (
                    args
                    and len(args) >= 1
                    and args[0] is not None
                    and args[0].t == ida_hexrays.mop_n
                ):
                    const_mop = args[0]

        if const_mop is not None and getattr(const_mop, "nnn", None):
            const_val = int(const_mop.nnn.value)
            const_size = const_mop.size

            tree = AstConstant(hex(const_val), const_val, const_size)
            tree.mop = const_mop
            tree.dest_size = const_size

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "[mop_to_ast_internal] Collapsed call-with-constant to leaf 0x%X (size=%d)",
                    const_val,
                    const_size,
                )

            new_index = len(context.unique_asts)
            tree.ast_index = new_index
            context.unique_asts.append(tree)
            context.mop_key_to_index[key] = new_index
            return tree

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
            if logger.isEnabledFor(logging.DEBUG):
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

            if logger.isEnabledFor(logging.DEBUG):
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
        # Treat an embedded ldc instruction as a constant leaf.
        ldc_src = mop.d.l
        if ldc_src is not None and ldc_src.t == ida_hexrays.mop_n:
            const_val = int(ldc_src.nnn.value)
            const_size = ldc_src.size
            tree = AstConstant(hex(const_val), const_val, const_size)
            tree.mop = ldc_src  # keep original constant mop
            tree.dest_size = const_size
        new_index = len(context.unique_asts)
        tree.ast_index = new_index
        context.unique_asts.append(tree)
        context.mop_key_to_index[key] = new_index
        return tree

    # Fallback for any unhandled mop: treat as a leaf.
    # This is for simple operands (registers, stack vars) or complex
    # instructions that are not part of our MBA analysis.
    if (
        mop.t != ida_hexrays.mop_d
        or (mop.d.opcode not in MBA_RELATED_OPCODES)
        or mop.d.l is None
        or mop.d.r is None
    ):
        tree: AstBase
        if mop.t == ida_hexrays.mop_n:
            const_val = int(mop.nnn.value)
            const_size = mop.size
            tree = AstConstant(hex(const_val), const_val, const_size)
            tree.dest_size = const_size
        elif mop.t == ida_hexrays.mop_f:
            """Handle typed-immediate wrappers produced by Hex-Rays.

            Typical example:  <fast:_DWORD #0xDEADBEEF.4,char #4.1>.4
            In most cases the numeric value is stored in *f.args[0]*, but it is
            not guaranteed that *mop.f* or the *args* list exists on all Ida
            versions/builds.  We therefore probe carefully and, when we do find
            the value, create a real *AstConstant* **and** keep the inner
            mop_n so that the evaluator recognises it as a constant later on.
            """

            const_val: int | None = None
            const_size: int | None = None

            f_info = getattr(mop, "f", None)
            if f_info and getattr(f_info, "args", None):
                args = f_info.args
                if (
                    args
                    and len(args) >= 1
                    and args[0] is not None
                    and args[0].t == ida_hexrays.mop_n
                ):
                    const_val = int(args[0].nnn.value)
                    const_size = mop.size or args[0].size

            if const_val is not None and const_size is not None:
                # Success: build a constant leaf backed by the *inner* mop_n
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "[mop_to_ast_internal] Extracted constant 0x%X (size=%d) from mop_f wrapper",
                        const_val,
                        const_size,
                    )
                tree = AstConstant(hex(const_val), const_val, const_size)
                tree.mop = args[0]  # Preserve the numeric mop for evaluators
                tree.dest_size = const_size
            else:
                # Could not extract – fall back to generic leaf so caller can
                # still see something meaningful in debug output.
                tree = AstLeaf(format_mop_t(mop))
                tree.mop = mop
                tree.dest_size = mop.size
        else:
            tree = AstLeaf(format_mop_t(mop))
            if logger.isEnabledFor(logging.DEBUG):
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
    _log_mop_tree(mop)
    return None


def mop_to_ast(mop: ida_hexrays.mop_t) -> AstProxy | None:
    """
    Converts a mop_t to an AST node, with caching to avoid re-computation.

    Returns a deep copy of the cached AST to prevent side-effects from
    mutations by the caller.
    """

    # 1. Create a stable, hashable key from the mop_t object.
    cache_key = get_mop_key(mop)

    # 2. Check if the result is already in the cache.
    if _cache_lookup := MOP_TO_AST_CACHE.get(cache_key):
        return AstProxy(_cache_lookup) if _cache_lookup is not None else None

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


def minsn_to_ast(instruction: ida_hexrays.minsn_t) -> AstProxy | None:
    try:
        # Early filter: forbidden opcodes
        if instruction.opcode in MINSN_TO_AST_FORBIDDEN_OPCODES:
            if logger.isEnabledFor(logging.DEBUG):
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
        if (
            instruction.opcode not in MBA_RELATED_OPCODES
            and not _is_rotate_helper_call(instruction)
        ):
            if logger.isEnabledFor(logging.DEBUG):
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

        # NEW: Shortcut - treat helper call whose result is already a literal as a constant leaf
        if instruction.opcode == ida_hexrays.m_call and instruction.d is not None:
            dest_mop = instruction.d
            const_mop = None

            # Direct constant result
            if dest_mop.t == ida_hexrays.mop_n:
                const_mop = dest_mop
            # Or destination is an ldc wrapping a constant
            elif (
                dest_mop.t == ida_hexrays.mop_d
                and dest_mop.d is not None
                and dest_mop.d.opcode == ida_hexrays.m_ldc
                and dest_mop.d.l is not None
                and dest_mop.d.l.t == ida_hexrays.mop_n
            ):
                const_mop = dest_mop.d.l

            # Case C: typed-immediate constant packed in mop_f
            elif dest_mop.t == ida_hexrays.mop_f and getattr(dest_mop, "f", None):
                args = dest_mop.f.args
                if (
                    args
                    and len(args) >= 1
                    and args[0] is not None
                    and args[0].t == ida_hexrays.mop_n
                ):
                    const_mop = args[0]

            if const_mop is not None:
                const_value = int(const_mop.nnn.value)
                const_size = const_mop.size

                leaf = AstConstant(hex(const_value), const_value, const_size)
                leaf.mop = const_mop  # preserve original constant mop
                leaf.dest_size = const_size
                leaf.ea = sanitize_ea(instruction.ea)

                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "[minsn_to_ast] Collapsed call with constant destination to leaf 0x%X (size=%d)",
                        const_value,
                        const_size,
                    )

                leaf.freeze()
                return AstProxy(leaf)

        # Transparent-call shortcut: no args, computation stored in destination mop_d
        if (
            instruction.opcode == ida_hexrays.m_call
            and (instruction.r is None or instruction.r.t == ida_hexrays.mop_z)
            and instruction.d is not None
            and instruction.d.t == ida_hexrays.mop_d
        ):
            if logger.isEnabledFor(logging.DEBUG):
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
            if logger.isEnabledFor(logging.DEBUG):
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
            return None
        tmp.dst_mop = instruction.d
        return tmp
    except RuntimeError as e:
        logger.error(
            "Error while transforming instruction %s: %s",
            format_minsn_t(instruction),
            e,
        )
        return None


def _is_rotate_helper_call(ins: ida_hexrays.minsn_t) -> bool:
    """Return True if *ins* is a call to one of Hex-Rays' synthetic
    rotate helpers (__ROL* / __ROR*).

    The folding pass treats those helpers as pure arithmetic, so we
    want to keep them instead of discarding them as “unsupported”.
    """

    if ins is None or ins.opcode != ida_hexrays.m_call:
        return False

    func_mop = ins.l
    if func_mop is None or func_mop.t != ida_hexrays.mop_h:
        return False

    helper_name: str = (func_mop.helper or "").lstrip("!")
    return helper_name.startswith("__ROL") or helper_name.startswith("__ROR")