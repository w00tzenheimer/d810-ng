from __future__ import annotations

import abc
import copy
import logging
import typing
from typing import Dict, List, Tuple, Union

from d810.errors import AstEvaluationException
from d810.hexrays_formatters import format_minsn_t, format_mop_t
from d810.hexrays_helpers import (
    AND_TABLE,
    MBA_RELATED_OPCODES,
    MINSN_TO_AST_FORBIDDEN_OPCODES,
    OPCODES_INFO,
    Z3_SPECIAL_OPERANDS,
    equal_mops_ignore_size,
)
from d810.utils import (
    get_add_cf,
    get_add_of,
    get_parity_flag,
    get_sub_of,
    signed_to_unsigned,
    unsigned_to_signed,
)

import ida_hexrays

logger = logging.getLogger("D810")


class AstInfo(object):
    def __init__(self, ast: AstNode | AstLeaf, number_of_use: int):
        self.ast = ast
        self.number_of_use = number_of_use

    def __str__(self):
        return f"{self.ast} used {self.number_of_use} times: {format_mop_t(self.ast.mop) if self.ast.mop else 0}"


class AstBase(abc.ABC):

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
                    opcode_list += [ast_info.ast.opcode] * ast_info.number_of_use

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
        cst_mop = ida_hexrays.mop_t()
        cst_mop.make_number(cst_value & AND_TABLE[cst_size], cst_size)
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

    def evaluate(self, dict_index_to_value):
        if self.ast_index in dict_index_to_value:
            return dict_index_to_value[self.ast_index]
        if self.dest_size is None:
            raise ValueError("dest_size is None")

        res_mask = AND_TABLE[self.dest_size]

        if self.opcode == ida_hexrays.m_mov:
            return (self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == ida_hexrays.m_neg:
            return (-self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == ida_hexrays.m_lnot:
            return self.left.evaluate(dict_index_to_value) != 0
        elif self.opcode == ida_hexrays.m_bnot:
            return (self.left.evaluate(dict_index_to_value) ^ res_mask) & res_mask
        elif self.opcode == ida_hexrays.m_xds:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            return signed_to_unsigned(left_value_signed, self.dest_size) & res_mask
        elif self.opcode == ida_hexrays.m_xdu:
            return (self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == ida_hexrays.m_low:
            return (self.left.evaluate(dict_index_to_value)) & res_mask
        elif self.opcode == ida_hexrays.m_add:
            return (
                self.left.evaluate(dict_index_to_value)
                + self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_sub:
            return (
                self.left.evaluate(dict_index_to_value)
                - self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_mul:
            return (
                self.left.evaluate(dict_index_to_value)
                * self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_udiv:
            return (
                self.left.evaluate(dict_index_to_value)
                // self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_sdiv:
            return (
                self.left.evaluate(dict_index_to_value)
                // self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_umod:
            return (
                self.left.evaluate(dict_index_to_value)
                % self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_smod:
            return (
                self.left.evaluate(dict_index_to_value)
                % self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_or:
            return (
                self.left.evaluate(dict_index_to_value)
                | self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_and:
            return (
                self.left.evaluate(dict_index_to_value)
                & self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_xor:
            return (
                self.left.evaluate(dict_index_to_value)
                ^ self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_shl:
            return (
                self.left.evaluate(dict_index_to_value)
                << self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_shr:
            return (
                self.left.evaluate(dict_index_to_value)
                >> self.right.evaluate(dict_index_to_value)
            ) & res_mask
        elif self.opcode == ida_hexrays.m_sar:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            res_signed = left_value_signed >> self.right.evaluate(dict_index_to_value)
            return signed_to_unsigned(res_signed, self.dest_size) & res_mask
        elif self.opcode == ida_hexrays.m_cfadd:
            tmp = get_add_cf(
                self.left.evaluate(dict_index_to_value),
                self.right.evaluate(dict_index_to_value),
                self.left.dest_size,
            )
            return tmp & res_mask
        elif self.opcode == ida_hexrays.m_ofadd:
            tmp = get_add_of(
                self.left.evaluate(dict_index_to_value),
                self.right.evaluate(dict_index_to_value),
                self.left.dest_size,
            )
            return tmp & res_mask
        elif self.opcode == ida_hexrays.m_sets:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            res = 1 if left_value_signed < 0 else 0
            return res & res_mask
        elif self.opcode == ida_hexrays.m_seto:
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
        elif self.opcode == ida_hexrays.m_setnz:
            res = (
                1
                if self.left.evaluate(dict_index_to_value)
                != self.right.evaluate(dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setz:
            res = (
                1
                if self.left.evaluate(dict_index_to_value)
                == self.right.evaluate(dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setae:
            res = (
                1
                if self.left.evaluate(dict_index_to_value)
                >= self.right.evaluate(dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setb:
            res = (
                1
                if self.left.evaluate(dict_index_to_value)
                < self.right.evaluate(dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif self.opcode == ida_hexrays.m_seta:
            res = (
                1
                if self.left.evaluate(dict_index_to_value)
                > self.right.evaluate(dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setbe:
            res = (
                1
                if self.left.evaluate(dict_index_to_value)
                <= self.right.evaluate(dict_index_to_value)
                else 0
            )
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setg:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.right.evaluate(dict_index_to_value), self.right.dest_size
            )
            res = 1 if left_value_signed > right_value_signed else 0
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setge:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.right.evaluate(dict_index_to_value), self.right.dest_size
            )
            res = 1 if left_value_signed >= right_value_signed else 0
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setl:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.right.evaluate(dict_index_to_value), self.right.dest_size
            )
            res = 1 if left_value_signed < right_value_signed else 0
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setle:
            left_value_signed = unsigned_to_signed(
                self.left.evaluate(dict_index_to_value), self.left.dest_size
            )
            right_value_signed = unsigned_to_signed(
                self.right.evaluate(dict_index_to_value), self.right.dest_size
            )
            res = 1 if left_value_signed <= right_value_signed else 0
            return res & res_mask
        elif self.opcode == ida_hexrays.m_setp:
            res = get_parity_flag(
                self.left.evaluate(dict_index_to_value),
                self.right.evaluate(dict_index_to_value),
                self.left.dest_size,
            )
            return res & res_mask
        else:
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
            return "Error_AstNode"
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstNode: {0}".format(e))
            return "Error_AstNode"

    def __deepcopy__(self, memo):
        """
        Creates a deep copy of the AstNode and its children.
        The 'memo' dictionary is used by deepcopy to handle cycles.
        """
        # Create a new instance without calling __init__
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result

        # Deepcopy the children recursively
        result.left = copy.deepcopy(self.left, memo)
        result.right = copy.deepcopy(self.right, memo)
        result.dst = copy.deepcopy(self.dst, memo)

        # Copy simple attributes
        result.opcode = self.opcode
        result.mop = self.mop  # Copy reference, not the object itself
        result.dst_mop = self.dst_mop  # Copy reference
        result.dest_size = self.dest_size
        result.ea = self.ea
        result.ast_index = self.ast_index

        # Initialize transient/computed attributes to their default state
        # or deepcopy them if they represent persistent state.
        result.is_candidate_ok = False
        result.leafs = []
        result.leafs_by_name = {}
        result.opcodes = list(self.opcodes)  # Create a copy of the list
        result.sub_ast_info_by_index = copy.deepcopy(self.sub_ast_info_by_index, memo)

        # Initialize the dict superclass
        super(AstNode, result).__init__()

        return result

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
        self.ast_index = None

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
        return dict_index_to_value.get(self.ast_index)

    def get_depth_signature(self, depth):
        if depth == 1:
            if self.is_constant():
                return ["C"]
            return ["L"]
        else:
            return ["N"] * (2 ** (depth - 1))

    def __str__(self):
        try:
            if self.is_constant() and self.mop is not None:
                return "{0}".format(self.mop.nnn.value)
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

    def __deepcopy__(self, memo):
        """
        Creates a deep copy of the AstLeaf.
        The 'memo' dictionary is used by deepcopy to handle cycles.
        """
        # Create a new instance without calling __init__ to avoid side effects
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result

        # Copy attributes. The 'mop' is a reference to an external object,
        # so we don't deepcopy it, we just copy the reference.
        result.name = self.name
        result.ast_index = self.ast_index
        result.mop = self.mop
        result.dest_size = self.dest_size
        result.ea = self.ea

        # Initialize transient or computed attributes to their default state
        result.z3_var = None
        result.z3_var_name = None
        result.sub_ast_info_by_index = copy.deepcopy(self.sub_ast_info_by_index, memo)

        return result


class AstConstant(AstLeaf):
    def __init__(self, name, expected_value=None, expected_size=None):
        super().__init__(name)
        self.expected_value = expected_value
        self.expected_size = expected_size

    @property
    def value(self):
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

    def __str__(self):
        try:
            if self.mop is not None and self.mop.t == ida_hexrays.mop_n:
                return "0x{0:x}".format(self.mop.nnn.value)
            if self.expected_value is not None:
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


MopCacheKey = tuple[int, str]


# The cache should be managed in a scope that persists across calls.
# A global variable is a common way to do this in IDA scripts.
MOP_TO_AST_CACHE: Dict[MopCacheKey, AstBase] = {}


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


def clear_mop_to_ast_cache():
    """
    Call this when the analysis context changes (e.g., new function)
    to prevent using stale data.
    """
    global MOP_TO_AST_CACHE
    MOP_TO_AST_CACHE.clear()


def mop_to_ast_internal(
    mop: ida_hexrays.mop_t, context: AstBuilderContext
) -> AstBase | None:
    if mop is None:
        return None

    # 1. Create the unique, hashable key for the current mop.
    key = (mop.valnum, mop.dstr())

    # 2. OPTIMIZATION: Check if this mop has already been processed.
    # This is our O(1) average-time lookup.
    if key in context.mop_key_to_index:
        # It's a hit! We've seen this sub-expression before.
        # Retrieve its index and return the already-created AST object.
        # This prunes the entire recursive branch, saving huge amounts of work.
        existing_index = context.mop_key_to_index[key]
        return context.unique_asts[existing_index]

    # 3. If it's a miss, we need to build the AST node.
    # This logic is the same as before.
    if mop.t != ida_hexrays.mop_d or (mop.d.opcode not in MBA_RELATED_OPCODES):
        # This is a leaf node (register, constant, variable, etc.)
        tree = AstLeaf(format_mop_t(mop))
        tree.mop = mop
        dest_size = mop.size if mop.t != ida_hexrays.mop_d else mop.d.d.size
        tree.dest_size = dest_size
    else:
        # This is an internal node (operation). Recurse for children.
        # Pass the SAME context object down.
        left_ast = mop_to_ast_internal(mop.d.l, context)
        right_ast = mop_to_ast_internal(mop.d.r, context)
        dst_ast = mop_to_ast_internal(
            mop.d.d, context
        )  # This seems unusual, but following original logic

        tree = AstNode(mop.d.opcode, left_ast, right_ast, dst_ast)
        tree.mop = mop
        tree.dest_size = mop.d.d.size
        tree.ea = mop.d.ea

    # 4. The node is built. Now add it to our context as a new unique element.
    # This replaces the old `check_and_add_to_list` call.
    new_index = len(context.unique_asts)
    tree.ast_index = new_index
    context.unique_asts.append(tree)

    # CRUCIAL: Update the map so we can find this node quickly next time.
    context.mop_key_to_index[key] = new_index

    return tree


def mop_to_ast(mop: ida_hexrays.mop_t) -> AstProxy | None:
    """
    Converts a mop_t to an AST node, with caching to avoid re-computation.

    Returns a deep copy of the cached AST to prevent side-effects from
    mutations by the caller.
    """
    if mop is None:
        return None

    # 1. Create a stable, hashable key from the mop_t object.
    cache_key = (mop.valnum, mop.dstr())

    # 2. Check if the result is already in the cache.
    if cache_key in MOP_TO_AST_CACHE:
        cached_ast = MOP_TO_AST_CACHE[cache_key]
        # Return a DEEP COPY of the cached object. This is critical.
        return AstProxy(cached_ast)
        # return copy.deepcopy(cached_ast)

    builder_context = AstBuilderContext()
    # Start the optimized recursive build.
    mop_ast = mop_to_ast_internal(mop, builder_context)
    if mop_ast is None:
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

    # 5. Return a deep copy to the caller for safety.
    return AstProxy(mop_ast)


# def check_and_add_to_list(
#     new_ast: Union[AstNode, AstLeaf], known_ast_list: List[Union[AstNode, AstLeaf]]
# ):
#     is_new_ast_known = False
#     for existing_elt in known_ast_list:
#         if equal_mops_ignore_size(new_ast.mop, existing_elt.mop):
#             new_ast.ast_index = existing_elt.ast_index
#             is_new_ast_known = True
#             break

#     if not is_new_ast_known:
#         ast_index = len(known_ast_list)
#         new_ast.ast_index = ast_index
#         known_ast_list.append(new_ast)


# def mop_to_ast_internal(
#     mop: ida_hexrays.mop_t, ast_list: list[AstNode | AstLeaf]
# ) -> Union[None, AstNode, AstLeaf]:
#     if mop is None:
#         return None

#     if mop.t != ida_hexrays.mop_d or (mop.d.opcode not in MBA_RELATED_OPCODES):
#         tree = AstLeaf(format_mop_t(mop))
#         tree.mop = mop
#         dest_size = mop.size if mop.t != ida_hexrays.mop_d else mop.d.d.size
#         tree.dest_size = dest_size
#     else:
#         left_ast = mop_to_ast_internal(mop.d.l, ast_list)
#         right_ast = mop_to_ast_internal(mop.d.r, ast_list)
#         dst_ast = mop_to_ast_internal(mop.d.d, ast_list)
#         tree = AstNode(mop.d.opcode, left_ast, right_ast, dst_ast)
#         tree.mop = mop
#         tree.dest_size = mop.d.d.size
#         tree.ea = mop.d.ea

#     check_and_add_to_list(tree, ast_list)
#     return tree


# def mop_to_ast(mop: ida_hexrays.mop_t) -> AstNode | AstLeaf | None:
#     mop_ast = mop_to_ast_internal(mop, [])
#     if mop_ast is None:
#         return None

#     mop_ast.compute_sub_ast()
#     return mop_ast


def minsn_to_ast(instruction: ida_hexrays.minsn_t) -> AstNode | AstLeaf | None:
    try:
        if instruction.opcode in MINSN_TO_AST_FORBIDDEN_OPCODES:
            # To avoid error 50278
            return None

        ins_mop = ida_hexrays.mop_t()
        ins_mop.create_from_insn(instruction)

        if instruction.opcode == ida_hexrays.m_mov:
            tmp = AstNode(ida_hexrays.m_mov, mop_to_ast(ins_mop))
            tmp.mop = ins_mop
            tmp.dest_size = instruction.d.size
            tmp.ea = instruction.ea
            tmp.dst_mop = instruction.d
            return tmp

        tmp = mop_to_ast(ins_mop)
        tmp.dst_mop = instruction.d
        return tmp
    except RuntimeError as e:
        logger.error(
            "Error while transforming instruction {0}: {1}".format(
                format_minsn_t(instruction), e
            )
        )
        return None
