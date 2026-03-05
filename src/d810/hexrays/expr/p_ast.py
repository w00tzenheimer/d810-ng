from __future__ import annotations

import abc
import dataclasses
import ida_hexrays
import idaapi

import d810.core.typing as typing
from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.core.bits import (
    get_add_cf,
    get_add_of,
    get_parity_flag,
    get_sub_of,
    signed_to_unsigned,
    unsigned_to_signed,
)
from d810.core import MOP_CONSTANT_CACHE
from d810.hexrays.utils.hexrays_formatters import (
    format_mop_t,
    mop_type_to_string,
    opcode_to_string,
)
from d810.hexrays.utils.hexrays_helpers import (
    AND_TABLE,
    OPCODES_INFO,
    Z3_SPECIAL_OPERANDS,
    equal_mops_ignore_size,
)
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.core import NOT_GIVEN, NotGiven

logger = getLogger(__name__)


# Pre-computed "N" signature lists for depth signatures.
# _N_SIGS[k] == ["N"] * (2 ** k) for k in 0..7 (covers depths up to 8).
_N_SIGS: tuple[list[str], ...] = tuple(["N"] * (2**k) for k in range(8))


def _get_n_sig(k: int) -> list[str]:
    """Return cached ["N"] * (2**k) list, or compute if k >= 8."""
    if k < len(_N_SIGS):
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
    ast: AstNode | AstLeaf
    number_of_use: int

    def __str__(self):
        return f"{self.ast} used {self.number_of_use} times: {format_mop_t(self.ast.mop) if self.ast.mop else 0}"


class AstBase:

    sub_ast_info_by_index: dict[int, AstInfo] = {}
    mop: ida_hexrays.mop_t | MopSnapshot | None = None
    dest_size: int | None = None
    ea: int | None = None
    ast_index: int | None = None
    ins: object = None

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
    def get_leaf_list(self) -> list[AstLeaf]: ...

    @abc.abstractmethod
    def reset_mops(self) -> None: ...

    @abc.abstractmethod
    def _copy_mops_from_ast(self, other: AstBase, read_only: bool = False) -> bool: ...

    @abc.abstractmethod
    def create_mop(self, ea: int) -> ida_hexrays.mop_t: ...

    @abc.abstractmethod
    def get_pattern(self) -> str: ...

    @abc.abstractmethod
    def get_depth_signature(self, depth: int) -> list[str]: ...

    def __bool__(self) -> bool:
        return True


class AstNode(AstBase):
    def __init__(
        self,
        opcode: int | None = None,
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
        self.is_candidate_ok = False

        self.leafs = []
        self.leafs_by_name = {}

        self.ast_index = 0
        self.sub_ast_info_by_index = {}

        self.func_name: str = ""
        self._is_frozen = False  # All newly created nodes are mutable by default
        self._depth_sig_cache: dict[int, list[str]] = {}  # Cache for get_depth_signature

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
        if self.mop is None:
            return 0
        if isinstance(self.mop, MopSnapshot):
            return self.mop.size
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
            mop = ast_info.ast.mop
            if mop is not None:
                mop_t = mop.t if isinstance(mop, MopSnapshot) else (mop.t if hasattr(mop, 't') else ida_hexrays.mop_z)
                if mop_t != ida_hexrays.mop_z:
                    if ast_info.ast.is_leaf():
                        if ast_info.ast.is_constant():
                            value = mop.value if isinstance(mop, MopSnapshot) else mop.nnn.value
                            cst_list.append(value)
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
        leaf.mop = MopSnapshot.from_mop(leaf_mop)
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
        def _equal_pattern_binding_mops(mop_left, mop_right) -> bool:
            """Pattern-binding equality that ignores mop_d destination artifacts.

            The same logical subexpression can be materialized into different
            temporaries (different destination registers) along a block. For
            repeated pattern variables we care about expression identity, not the
            destination carrier register of nested m_insn operands.
            """
            try:
                left = mop_left.to_mop() if isinstance(mop_left, MopSnapshot) else mop_left
                right = mop_right.to_mop() if isinstance(mop_right, MopSnapshot) else mop_right
                if (
                    left is not None
                    and right is not None
                    and left.t == ida_hexrays.mop_d
                    and right.t == ida_hexrays.mop_d
                ):
                    left_ins = ida_hexrays.minsn_t(left.d)
                    right_ins = ida_hexrays.minsn_t(right.d)
                    left_ins.d = ida_hexrays.mop_t()
                    right_ins.d = ida_hexrays.mop_t()
                    left_ins.d.erase()
                    right_ins.d.erase()
                    return left_ins.equal_insns(right_ins, ida_hexrays.EQ_IGNSIZE)
            except Exception:
                pass
            return equal_mops_ignore_size(mop_left, mop_right)

        self.leafs = self.get_leaf_list()
        self.leafs_by_name = {}
        self.is_candidate_ok = True

        for leaf in self.leafs:
            ref_leaf = self.leafs_by_name.get(leaf.name)
            if ref_leaf is not None and leaf.mop is not None:
                if not _equal_pattern_binding_mops(ref_leaf.mop, leaf.mop):
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
            # Delegate to leaf-specific update so AstConstant can copy
            # expected_value/expected_size for computed constants.
            if not leaf.update_leafs_mop(other, other2):
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

    def get_depth_signature(self, depth):
        # Check cache first (fast path for frozen nodes)
        cached = self._depth_sig_cache.get(depth)
        if cached is not None:
            return cached

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
        new_node._depth_sig_cache = {}  # Fresh cache for cloned object
        new_node.func_name = self.func_name

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
        self.z3_var_name: str | NotGiven = NOT_GIVEN

        self.dest_size = None
        self.ea = None
        self._is_frozen = False  # All newly created nodes are mutable by default
        self.sub_ast_info_by_index = {}
        self._depth_sig_cache: dict[int, list[str]] = {}  # Cache for get_depth_signature

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
        if isinstance(self.mop, MopSnapshot):
            return self.mop.is_constant
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
        # AstConstant carries extra matching state not present on AstLeaf.
        if hasattr(self, "expected_value"):
            new_leaf.expected_value = self.expected_value
        if hasattr(self, "expected_size"):
            new_leaf.expected_size = self.expected_size

        # Initialize transient state
        new_leaf.z3_var = None
        new_leaf.z3_var_name = NOT_GIVEN
        new_leaf.sub_ast_info_by_index = {}  # Start fresh
        new_leaf._depth_sig_cache = {}  # Fresh cache for cloned object

        # Cloned objects start mutable by definition
        new_leaf._is_frozen = False

        return new_leaf

    def __getitem__(self, name: str) -> AstLeaf:
        if name == self.name:
            return self
        raise KeyError

    @property
    def size(self):
        if self.mop is None:
            return 0
        if isinstance(self.mop, MopSnapshot):
            return self.mop.size
        return self.mop.size

    @property
    def dst_mop(self):
        return self.mop

    @dst_mop.setter
    def dst_mop(self, mop):
        self.mop = MopSnapshot.from_mop(mop) if mop is not None else None

    @property
    def value(self):
        if self.is_constant() and self.mop is not None:
            if isinstance(self.mop, MopSnapshot):
                return self.mop.value
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

        # 2. Handle both MopSnapshot and raw mop_t
        if isinstance(self.mop, MopSnapshot):
            # Reconstruct from snapshot
            return self.mop.to_mop()
        else:
            # Legacy path: clone the mop_t
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
            if isinstance(self.mop, MopSnapshot):
                return "AstConstant('{0}', {0})".format(self.mop.value)
            return "AstConstant('{0}', {0})".format(self.mop.nnn.value)
        if self.ast_index is not None:
            return "AstLeaf('x_{0}')".format(self.ast_index)
        if self.name is not None:
            return "AstLeaf('{0}')".format(self.name)

    def get_depth_signature(self, depth):
        # Check cache first
        cached = self._depth_sig_cache.get(depth)
        if cached is not None:
            return cached

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
                if isinstance(self.mop, MopSnapshot):
                    return "{0}".format(hex(self.mop.value))
                return "{0}".format(hex(self.mop.nnn.value))
            if self.z3_var_name is not NOT_GIVEN:
                return self.z3_var_name
            if self.ast_index is not None:
                return "x_{0}".format(self.ast_index)
            if self.mop is not None:
                if isinstance(self.mop, MopSnapshot):
                    # Format snapshot - use a simple representation
                    return f"mop_snapshot_{self.mop.t}"
                return format_mop_t(self.mop)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstLeaf: {0}".format(e))
            return "Error_AstLeaf"

    def __repr__(self):
        return f"AstLeaf('{str(self)}')"


class AstConstant(AstLeaf):
    def __init__(self, name, expected_value=None, expected_size=None):
        super().__init__(name)
        self.expected_value = expected_value
        self.expected_size = expected_size

    @property
    def value(self):
        if self.mop is not None:
            if isinstance(self.mop, MopSnapshot):
                return self.mop.value if self.mop.is_constant else self.expected_value
            if self.mop.t == ida_hexrays.mop_n:
                return self.mop.nnn.value
        # Fall back to expected_value for computed constants (e.g., c_res from constraints)
        return self.expected_value

    @typing.override
    def is_constant(self) -> bool:
        # An AstConstant is always constant, so return True
        return True

    def _copy_mops_from_ast(self, other, read_only: bool = False):
        if other.mop is not None:
            is_const = isinstance(other.mop, MopSnapshot) and other.mop.is_constant or \
                       (not isinstance(other.mop, MopSnapshot) and other.mop.t == ida_hexrays.mop_n)
            if not is_const:
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
                format_mop_t(other.mop) if not isinstance(other.mop, MopSnapshot) else f"MopSnapshot({other.mop.value})",
            )
        if not read_only:
            self.mop = other.mop
        if self.expected_value is None:
            if not read_only:
                if isinstance(other.mop, MopSnapshot):
                    self.expected_value = other.mop.value
                    self.expected_size = other.mop.size
                else:
                    self.expected_value = other.mop.nnn.value
                    self.expected_size = other.mop.size
            else:
                return True
        other_value = other.mop.value if isinstance(other.mop, MopSnapshot) else other.mop.nnn.value
        return self.expected_value == other_value

    def get_depth_signature(self, depth):
        # Check cache first (inherited from AstLeaf)
        cached = self._depth_sig_cache.get(depth)
        if cached is not None:
            return cached

        if depth == 1:
            result = ["C"]
        else:
            result = _get_n_sig(depth - 1)

        # Cache the result for frozen nodes
        if self._is_frozen:
            self._depth_sig_cache[depth] = result
        return result

    @typing.override
    def __str__(self):
        try:
            if self.mop is not None:
                if isinstance(self.mop, MopSnapshot) and self.mop.is_constant:
                    return "0x{0:x}".format(self.mop.value)
                elif not isinstance(self.mop, MopSnapshot) and self.mop.t == ida_hexrays.mop_n:
                    return "0x{0:x}".format(self.mop.nnn.value)
            if getattr(self, "expected_value", None) is not None:
                return "0x{0:x}".format(self.expected_value)
            return self.name
        except RuntimeError as e:
            logger.info("Error while calling __str__ on AstConstant: {0}".format(e))
            return "Error_AstConstant"

    @typing.override
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
            if isinstance(source_leaf.mop, MopSnapshot) and source_leaf.mop.is_constant:
                self.expected_value = source_leaf.mop.value
                self.expected_size = source_leaf.mop.size
            elif not isinstance(source_leaf.mop, MopSnapshot) and source_leaf.mop.t == ida_hexrays.mop_n:
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


class AstProxy(AstBase):

    def __init__(self, target_ast: AstBase):
        # The proxy initially holds a reference to the shared, frozen template
        self._target = target_ast

    def _ensure_mutable(self):
        """
        Ensures the target is mutable. If the target is frozen, clone it and
        replace our internal reference with the new, mutable clone.
        Skips cloning if already mutable.
        """
        if self._target.is_frozen:
            # Clone only if frozen (i.e., shared)
            self._target = self._target.clone()

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
            # Attribute not present on proxy -> delegate unconditionally.
            return getattr(super().__getattribute__("_target"), name)

        # If the proxy's value is a meaningless placeholder (None) but the
        # underlying object has a better value, return the latter instead.
        if val is None:
            target = super().__getattribute__("_target")
            return getattr(target, name)
        return val

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
    def get_leaf_list(self) -> list[AstLeaf]:
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
    @typing.override
    def get_depth_signature(self, depth: int) -> list[str]:
        return self._target.get_depth_signature(depth)

    @typing.override
    def __str__(self):
        return f"AstProxy({self._target.__class__.__name__}({str(self._target)}))"

    @typing.override
    def __repr__(self):
        return f"AstProxy({repr(self._target)})"

    # Explicitly forward critical leaf data that callers expect to access
    # directly.  Without these properties Python finds the *class*-level
    # attribute defined in AstBase (value = None) and never triggers
    # __getattr__, so evaluators see a leaf with no mop.

    # --- Mop -------------------------------------------------------------
    @property
    def mop(self):  # type: ignore[override]
        return self._target.mop

    @mop.setter
    def mop(self, value):  # noqa: ANN001
        self._ensure_mutable()
        self._target.mop = MopSnapshot.from_mop(value) if value is not None else None

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


def get_mop_key(mop: ida_hexrays.mop_t) -> tuple:
    """
    Generates a fast, hashable key from a mop_t's essential attributes.
    This is significantly faster than using mop.dstr().
    """
    t = mop.t

    # Hex-Rays assigns a new SSA value number (valnum) every time an operand is
    # produced, even when it represents the *same* memory/register location.
    # Including valnum in the cache key therefore forces the AST builder to
    # create a distinct AstLeaf for each SSA instance (x_0, x_6, ...), which
    # breaks pattern rules that expect a single variable.

    # We drop valnum from the key for all operand kinds except plain numeric
    # constants, where valnum is useful to avoid collisions when two literals
    # share the same size.

    key = (t, mop.size) if t != ida_hexrays.mop_n else (t, mop.size, mop.valnum)
    match t:
        case ida_hexrays.mop_n:
            nnn = mop.nnn
            if nnn is None:
                return key + (0,)
            return key + (nnn.value,)
        case ida_hexrays.mop_r:
            return key + (mop.r,)
        case ida_hexrays.mop_d:
            # Using the micro-instruction EA differentiates identical loads that
            # happen at different addresses, producing multiple leaves for the
            # same logical value.  Instead we rely on the operand text (dstr),
            # which is identical for identical expressions regardless of SSA
            # copy location.
            try:
                return key + (mop.dstr(),)
            except Exception:
                # As a last resort fall back to EA.
                return key + (mop.d.ea if mop.d else idaapi.BADADDR,)
        case ida_hexrays.mop_S:
            return key + (mop.s.off,)
        case ida_hexrays.mop_v:
            return key + (mop.g,)
        case ida_hexrays.mop_l:
            return key + (mop.l.idx, mop.l.off)
        case ida_hexrays.mop_b:
            return key + (mop.b,)
        case ida_hexrays.mop_h:
            return key + (mop.helper,)
        case ida_hexrays.mop_str:
            return key + (mop.cstr,)
        case _:
            # For other types, including complex ones like mop_f, mop_a, etc.,
            # and mop_z, we fall back to the slower but safer dstr().
            # This is a deliberate trade-off for robustness.
            try:
                return key + (mop.dstr(),)
            except Exception:
                # As a last resort, if dstr() fails, use a placeholder.
                # This can happen for uninitialized or unusual mop_t instances.
                logger.warning(
                    "get_mop_key: Unsupported mop_t type: %s, returning placeholder",
                    mop_type_to_string(t),
                )
                return key + (f"unsupported_mop_t_{t}",)
