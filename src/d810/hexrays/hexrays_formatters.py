import functools
import pathlib
import typing

# Try to import IDA modules, allow module to be imported for unit testing
try:
    import ida_hexrays
    import idaapi
    IDA_AVAILABLE = True
except ImportError:
    # Mock for unit testing
    IDA_AVAILABLE = False
    idaapi = None  # type: ignore

    class _MockIDAHexrays:  # type: ignore
        class mbl_array_t:
            pass
        class minsn_t:
            pass
        class mop_t:
            pass
        class vd_printer_t:
            def __init__(self):
                pass

        # Operand types for type comparisons
        mop_d = 4
        mop_a = 10
        mop_f = 8
        mop_l = 9
        mop_S = 5
        mop_c = 12
        mop_p = 14
        mop_sc = 15
        mop_n = 2
        mop_fn = 13
        mop_r = 1
        mop_v = 6
        mop_b = 7
        mop_str = 3
        mop_h = 11

    ida_hexrays = _MockIDAHexrays()

from d810.core import getLogger
from d810.hexrays.hexrays_helpers import (
    MATURITY_TO_STRING_DICT,
    MOP_TYPE_TO_STRING_DICT,
    OPCODES_INFO,
    STRING_TO_MATURITY_DICT,
)

logger = getLogger(__name__)

_trans_table = str.maketrans(
    "", "", "".join(chr(i) for i in range(256) if not (0x20 <= i <= 0x7E))
)


@functools.lru_cache(maxsize=4096)
def _cached_format_minsn_t(ea: int, raw_repr: str) -> str:
    """Internal helper to cache the printable form of a *minsn_t*.

    The cache key is a tuple of the instruction's *ea* and the raw string
    returned by *minsn_t._print()*.  We include *raw_repr* in the key to avoid
    stale cache entries should the underlying instruction at *ea* change
    during microcode transformations.
    """
    # Filter out non-printable characters once and store the result.
    return raw_repr.translate(_trans_table)


def format_minsn_t(ins: ida_hexrays.minsn_t | None) -> str:
    """Return a printable representation of *ins*.

    The heavy-weight ``_print`` call is cached so subsequent requests for the
    same instruction (identified by its ``ea``) are virtually free.
    """
    if ins is None:
        return "minsn_t is None"

    raw = typing.cast(str, ins._print())
    return _cached_format_minsn_t(ins.ea, raw)


def mop_tree(mop: ida_hexrays.mop_t | None, depth: int = 0, max_depth: int = 8) -> str:
    """
    Recursively format a mop_t tree as a string for inspection.
    Returns a string representation of the tree.
    """
    lines = []
    indent = "  " * depth
    if mop is None:
        lines.append(f"{indent}<mop=None>")
        return "\n".join(lines)
    try:
        mop_type = mop.t if hasattr(mop, "t") else None
        if mop_type is None:
            lines.append(f"{indent}<mop_t type=None>")
            return "\n".join(lines)
        mop_str = str(mop.dstr()) if hasattr(mop, "dstr") else str(mop)
        lines.append(
            f"{indent}<mop_t type={mop_type_to_string(mop_type)} size={getattr(mop, 'size', None)} dstr={mop_str}>"
        )
        if depth >= max_depth:
            return "\n".join(lines)
        # Recurse for sub-operands
        # Recurse for all mop types that can have sub-operands
        if mop_type == ida_hexrays.mop_d and hasattr(mop, "d") and mop.d is not None:
            # mop_d: instruction, has l, r, d
            lines.append(mop_tree(getattr(mop.d, "l", None), depth + 1, max_depth))
            lines.append(mop_tree(getattr(mop.d, "r", None), depth + 1, max_depth))
            lines.append(mop_tree(getattr(mop.d, "d", None), depth + 1, max_depth))
        elif mop_type == ida_hexrays.mop_a and hasattr(mop, "a") and mop.a is not None:
            # mop_a: address, has v
            lines.append(mop_tree(getattr(mop.a, "v", None), depth + 1, max_depth))
        elif mop_type == ida_hexrays.mop_f and hasattr(mop, "f") and mop.f is not None:
            # mop_f: function call, has args
            for arg in getattr(mop.f, "args", []):
                lines.append(mop_tree(arg, depth + 1, max_depth))
        elif mop_type == ida_hexrays.mop_l and hasattr(mop, "l") and mop.l is not None:
            # mop_l: local variable reference, may have a parent (rarely useful)
            pass  # No recursion needed
        elif mop_type == ida_hexrays.mop_S and hasattr(mop, "s") and mop.s is not None:
            # mop_S: stack variable reference, may have a parent (rarely useful)
            pass  # No recursion needed
        elif mop_type == ida_hexrays.mop_c and hasattr(mop, "c") and mop.c is not None:
            # mop_c: switch cases, has cases (list of mop_t)
            for case in getattr(mop.c, "cases", []):
                lines.append(mop_tree(case, depth + 1, max_depth))
        elif (
            mop_type == ida_hexrays.mop_p
            and hasattr(mop, "pair")
            and mop.pair is not None
        ):
            # mop_p: pair, has l and h
            lines.append(mop_tree(getattr(mop.pair, "l", None), depth + 1, max_depth))
            lines.append(mop_tree(getattr(mop.pair, "h", None), depth + 1, max_depth))
        elif (
            mop_type == ida_hexrays.mop_sc
            and hasattr(mop, "scif")
            and mop.scif is not None
        ):
            # mop_sc: scif, has args
            for arg in getattr(mop.scif, "args", []):
                lines.append(mop_tree(arg, depth + 1, max_depth))
        # The following types do not have sub-operands to recurse into,
        # but we still want to print their values for inspection.
        if mop_type == ida_hexrays.mop_n and hasattr(mop, "nnn"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} number] value={getattr(mop.nnn, 'value', None)}"
            )
        elif mop_type == ida_hexrays.mop_fn and hasattr(mop, "fpc"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} float] value={getattr(mop.fpc, 'value', None)}"
            )
        elif mop_type == ida_hexrays.mop_r and hasattr(mop, "r"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} register] reg={getattr(mop, 'r', None)}"
            )
        elif mop_type == ida_hexrays.mop_v and hasattr(mop, "g"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} global] ea=0x{getattr(mop, 'g', None):X}"
            )
        elif mop_type == ida_hexrays.mop_b and hasattr(mop, "b"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} bit] bit={getattr(mop, 'b', None)}"
            )
        elif mop_type == ida_hexrays.mop_str and hasattr(mop, "cstr"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} string] value={repr(getattr(mop, 'cstr', None))}"
            )
        elif mop_type == ida_hexrays.mop_h and hasattr(mop, "helper"):
            lines.append(
                f"{indent}  [{mop_type_to_string(mop_type)} helper] name={repr(getattr(mop, 'helper', None))}"
            )
    except Exception as e:
        lines.append(f"{indent}<error logging mop: {e}>")
    return "\n".join(line for line in lines if line)


import dataclasses


@dataclasses.dataclass
class MopTreeLogger:
    max_depth: int = 8
    indent: str = ""
    child_indent: str = ""
    unicode: bool = False

    @staticmethod
    def describe_mop(mop):
        try:
            mop_type = mop.t if hasattr(mop, "t") else None
            if mop_type is None:
                return "<mop_t type=None>"
            mop_str = str(mop.dstr()) if hasattr(mop, "dstr") else str(mop)
            desc = f"<mop_t type={mop_type_to_string(mop_type)} size={getattr(mop, 'size', None)} valnum={getattr(mop, 'valnum', None)} dstr={mop_str}>"
            # Add value for leaf types
            if mop_type == ida_hexrays.mop_n and hasattr(mop, "nnn"):
                desc += f" [number] value={getattr(mop.nnn, 'value', None)}"
            elif mop_type == ida_hexrays.mop_fn and hasattr(mop, "fpc"):
                desc += f" [float] value={getattr(mop.fpc, 'value', None)}"
            elif mop_type == ida_hexrays.mop_r and hasattr(mop, "r"):
                desc += f" [register] reg={getattr(mop, 'r', None)}"
            elif mop_type == ida_hexrays.mop_v and hasattr(mop, "g"):
                desc += f" [global] ea=0x{getattr(mop, 'g', None):X}"
            elif mop_type == ida_hexrays.mop_b and hasattr(mop, "b"):
                desc += f" [bit] bit={getattr(mop, 'b', None)}"
            elif mop_type == ida_hexrays.mop_str and hasattr(mop, "cstr"):
                desc += f" [string] value={repr(getattr(mop, 'cstr', None))}"
            elif mop_type == ida_hexrays.mop_h and hasattr(mop, "helper"):
                desc += f" [helper] name={repr(getattr(mop, 'helper', None))}"
            return desc
        except Exception as e:
            return f"<error describing mop: {e}>"

    @staticmethod
    def get_children(mop):
        mop_type = mop.t if hasattr(mop, "t") else None
        children = []
        if mop_type == ida_hexrays.mop_d and hasattr(mop, "d") and mop.d is not None:
            # mop_d: instruction, has l, r, d
            children = [
                ("l", getattr(mop.d, "l", None)),
                ("r", getattr(mop.d, "r", None)),
                ("d", getattr(mop.d, "d", None)),
            ]
        elif mop_type == ida_hexrays.mop_a and hasattr(mop, "a") and mop.a is not None:
            children = [("v", getattr(mop.a, "v", None))]
        elif mop_type == ida_hexrays.mop_f and hasattr(mop, "f") and mop.f is not None:
            children = [
                (f"arg[{i}]", arg) for i, arg in enumerate(getattr(mop.f, "args", []))
            ]
        elif mop_type == ida_hexrays.mop_c and hasattr(mop, "c") and mop.c is not None:
            children = [
                (f"case[{i}]", case)
                for i, case in enumerate(getattr(mop.c, "cases", []))
            ]
        elif (
            mop_type == ida_hexrays.mop_p
            and hasattr(mop, "pair")
            and mop.pair is not None
        ):
            children = [
                ("l", getattr(mop.pair, "l", None)),
                ("h", getattr(mop.pair, "h", None)),
            ]
        elif (
            mop_type == ida_hexrays.mop_sc
            and hasattr(mop, "scif")
            and mop.scif is not None
        ):
            children = [
                (f"arg[{i}]", arg)
                for i, arg in enumerate(getattr(mop.scif, "args", []))
            ]
        # mop_l, mop_S: no recursion needed
        return [(name, child) for name, child in children if child is not None]

    def render(self, mop, indent, child_indent, depth):
        if mop is None:
            return f"{indent}<mop=None>\n"
        if depth >= self.max_depth:
            return f"{indent}<max depth reached>\n"
        try:
            desc = self.describe_mop(mop)
            children = self.get_children(mop)
            if not children:
                return f"{indent}{desc}\n"
            result = f"{indent}{desc}\n"
            last_idx = len(children) - 1
            indents = (
                {"├": "├─ ", "│": "│  ", "└": "└─ ", " ": "   "}
                if self.unicode
                else {"├": "|- ", "│": "|  ", "└": "`- ", " ": "   "}
            )
            for i, (name, child) in enumerate(children):
                if i < last_idx:
                    c_indent = child_indent + indents["├"]
                    cc_indent = child_indent + indents["│"]
                else:
                    c_indent = child_indent + indents["└"]
                    cc_indent = child_indent + indents[" "]
                # Show the field name for clarity
                result += f"{c_indent}[{name}]\n"
                result += self.render(
                    child, indent=cc_indent, child_indent=cc_indent, depth=depth + 1
                )
            return result
        except Exception as e:
            return f"{indent}<error logging mop: {e}>\n"

    @classmethod
    def log_mop_tree(
        cls,
        mop: "mop_t | None",
        *,
        max_depth: int = 8,
        indent: str = "",
        child_indent: str = "",
        unicode: bool = False,
    ) -> str:
        """
        Render a mop_t tree in a tree-like fashion, using unicode or ascii connectors.
        """
        renderer = cls(
            max_depth=max_depth,
            indent=indent,
            child_indent=child_indent,
            unicode=unicode,
        )
        return renderer.render(mop, indent, child_indent, 0)


def format_mop_t(mop_in: ida_hexrays.mop_t | None) -> str:
    if mop_in is None:
        return "mop_t is None"
    if mop_in.t > 15:
        # To avoid error 50581
        return "Unknown mop type {0}".format(mop_in.t)
    return mop_tree(mop_in, max_depth=0)


def format_mop_list(mop_list: list[ida_hexrays.mop_t]) -> str:
    return ", ".join([format_mop_t(x) for x in mop_list])


def maturity_to_string(maturity_level: int) -> str:
    return MATURITY_TO_STRING_DICT.get(
        maturity_level, "Unknown maturity: {0}".format(maturity_level)
    )


def string_to_maturity(maturity_string: str) -> int | None:
    """Convert a maturity name (with or without 'MMAT_' prefix) to its integer code."""
    # Normalize to upper-case
    key = maturity_string.upper()
    # Add prefix if missing
    if not key.startswith("MMAT_"):
        key = f"MMAT_{key}"
    return STRING_TO_MATURITY_DICT.get(key)


def mop_type_to_string(mop_type: int) -> str:
    return MOP_TYPE_TO_STRING_DICT.get(
        mop_type, "Unknown mop type: {0}".format(mop_type)
    )


def opcode_to_string(opcode: int) -> str:
    try:
        return OPCODES_INFO[opcode]["name"]
    except KeyError:
        return "Unknown opcode: {0}".format(opcode)


class mba_printer(ida_hexrays.vd_printer_t):
    def __init__(self):
        ida_hexrays.vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append(line.translate(_trans_table) + "\n")
        return 1


class block_printer(ida_hexrays.vd_printer_t):
    def __init__(self):
        ida_hexrays.vd_printer_t.__init__(self)
        self.block_ins = []

    def get_block_mc(self):
        return "\n".join(self.block_ins)

    def _print(self, indent, line):
        self.block_ins.append(line.translate(_trans_table))
        return 1


def write_mc_to_file(
    mba: ida_hexrays.mbl_array_t, filename: pathlib.Path, mba_flags: int = 0
) -> bool:
    if not mba:
        return False

    vp = mba_printer()
    mba.set_mba_flags(mba_flags)
    mba._print(vp)

    with filename.open("w", encoding="utf-8") as f:
        f.writelines(vp.get_mc())
    return True


def dump_microcode_for_debug(
    mba: ida_hexrays.mbl_array_t, log_dir_path: pathlib.Path, name: str = ""
):
    if isinstance(log_dir_path, str):
        log_dir_path = pathlib.Path(log_dir_path)
    mc_filename = log_dir_path / f"{mba.entry_ea:x}_maturity_{mba.maturity}_{name}.log"
    logger.info("Dumping microcode in file {0}...".format(mc_filename))
    write_mc_to_file(mba, mc_filename)


def sanitize_ea(ea: int) -> int:
    return ea & idaapi.BADADDR  # BADADDR = 0xFFFF_FFFF_FFFF_FFFF on x64
