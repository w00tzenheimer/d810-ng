import functools
import pathlib
import typing

import ida_hexrays
import idaapi
from ida_hexrays import mbl_array_t, minsn_t, mop_t, vd_printer_t

from d810.conf.loggers import getLogger
from d810.hexrays.hexrays_helpers import (
    MATURITY_TO_STRING_DICT,
    MOP_TYPE_TO_STRING_DICT,
    OPCODES_INFO,
    STRING_TO_MATURITY_DICT,
)

logger = getLogger("D810.helper")

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


def format_minsn_t(ins: minsn_t | None) -> str:
    """Return a printable representation of *ins*.

    The heavy-weight ``_print`` call is cached so subsequent requests for the
    same instruction (identified by its ``ea``) are virtually free.
    """
    if ins is None:
        return "minsn_t is None"

    raw = typing.cast(str, ins._print())
    return _cached_format_minsn_t(ins.ea, raw)


def format_mop_t(mop_in: mop_t | None) -> str:
    if mop_in is None:
        return "mop_t is None"
    if mop_in.t > 15:
        # To avoid error 50581
        return "Unknown mop type {0}".format(mop_in.t)
    return mop_in.dstr()


def format_mop_list(mop_list: list[mop_t]) -> str:
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


class mba_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append(line.translate(_trans_table) + "\n")
        return 1


class block_printer(vd_printer_t):
    def __init__(self):
        vd_printer_t.__init__(self)
        self.block_ins = []

    def get_block_mc(self):
        return "\n".join(self.block_ins)

    def _print(self, indent, line):
        self.block_ins.append(line.translate(_trans_table))
        return 1


def write_mc_to_file(
    mba: mbl_array_t, filename: pathlib.Path, mba_flags: int = 0
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
    mba: mbl_array_t, log_dir_path: pathlib.Path, name: str = ""
):
    if isinstance(log_dir_path, str):
        log_dir_path = pathlib.Path(log_dir_path)
    mc_filename = log_dir_path / f"{mba.entry_ea:x}_maturity_{mba.maturity}_{name}.log"
    logger.info("Dumping microcode in file {0}...".format(mc_filename))
    write_mc_to_file(mba, mc_filename)


def sanitize_ea(ea: int | None) -> int | None:
    if ea is None:
        return None
    return ea & idaapi.BADADDR  # BADADDR = 0xFFFF_FFFF_FFFF_FFFF on x64


def log_mop_tree(mop, depth=0, max_depth=8):
    indent = "  " * depth
    if mop is None:
        logger.info("%s<mop=None>", indent)
        return
    try:
        mop_type = mop.t if hasattr(mop, "t") else None
        if mop_type is None:
            logger.info("%s<mop_t type=None>", indent)
            return
        mop_str = str(mop.dstr()) if hasattr(mop, "dstr") else str(mop)
        logger.info(
            "%s<mop_t type=%s size=%s valnum=%s dstr=%s>",
            indent,
            mop_type_to_string(mop_type),
            getattr(mop, "size", None),
            getattr(mop, "valnum", None),
            mop_str,
        )
        if depth >= max_depth:
            logger.info("%s<max depth reached>", indent)
            return
        # Recurse for sub-operands
        # Recurse for all mop types that can have sub-operands
        if mop_type == ida_hexrays.mop_d and hasattr(mop, "d") and mop.d is not None:
            # mop_d: instruction, has l, r, d
            log_mop_tree(getattr(mop.d, "l", None), depth + 1, max_depth)
            log_mop_tree(getattr(mop.d, "r", None), depth + 1, max_depth)
            log_mop_tree(getattr(mop.d, "d", None), depth + 1, max_depth)
        elif mop_type == ida_hexrays.mop_a and hasattr(mop, "a") and mop.a is not None:
            # mop_a: address, has v
            log_mop_tree(getattr(mop.a, "v", None), depth + 1, max_depth)
        elif mop_type == ida_hexrays.mop_f and hasattr(mop, "f") and mop.f is not None:
            # mop_f: function call, has args
            for arg in getattr(mop.f, "args", []):
                log_mop_tree(arg, depth + 1, max_depth)
        elif mop_type == ida_hexrays.mop_l and hasattr(mop, "l") and mop.l is not None:
            # mop_l: local variable reference, may have a parent (rarely useful)
            pass  # No recursion needed
        elif mop_type == ida_hexrays.mop_S and hasattr(mop, "s") and mop.s is not None:
            # mop_S: stack variable reference, may have a parent (rarely useful)
            pass  # No recursion needed
        elif mop_type == ida_hexrays.mop_c and hasattr(mop, "c") and mop.c is not None:
            # mop_c: switch cases, has cases (list of mop_t)
            for case in getattr(mop.c, "cases", []):
                log_mop_tree(case, depth + 1, max_depth)
        elif (
            mop_type == ida_hexrays.mop_p
            and hasattr(mop, "pair")
            and mop.pair is not None
        ):
            # mop_p: pair, has l and h
            log_mop_tree(getattr(mop.pair, "l", None), depth + 1, max_depth)
            log_mop_tree(getattr(mop.pair, "h", None), depth + 1, max_depth)
        elif (
            mop_type == ida_hexrays.mop_sc
            and hasattr(mop, "scif")
            and mop.scif is not None
        ):
            # mop_sc: scif, has args
            for arg in getattr(mop.scif, "args", []):
                log_mop_tree(arg, depth + 1, max_depth)
        # The following types do not have sub-operands to recurse into,
        # but we still want to print their values for inspection.
        if mop_type == ida_hexrays.mop_n and hasattr(mop, "nnn"):
            logger.info(
                "%s  [%s number] value=%s",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop.nnn, "value", None),
            )
        elif mop_type == ida_hexrays.mop_fn and hasattr(mop, "fpc"):
            logger.info(
                "%s  [%s float] value=%s",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop.fpc, "value", None),
            )
        elif mop_type == ida_hexrays.mop_r and hasattr(mop, "r"):
            logger.info(
                "%s  [%s register] reg=%s",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop, "r", None),
            )
        elif mop_type == ida_hexrays.mop_v and hasattr(mop, "g"):
            logger.info(
                "%s  [%s global] ea=0x%X",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop, "g", None),
            )
        elif mop_type == ida_hexrays.mop_b and hasattr(mop, "b"):
            logger.info(
                "%s  [%s bit] bit=%s",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop, "b", None),
            )
        elif mop_type == ida_hexrays.mop_str and hasattr(mop, "cstr"):
            logger.info(
                "%s  [%s string] value=%r",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop, "cstr", None),
            )
        elif mop_type == ida_hexrays.mop_h and hasattr(mop, "helper"):
            logger.info(
                "%s  [%s helper] name=%r",
                indent,
                mop_type_to_string(mop_type),
                getattr(mop, "helper", None),
            )
    except Exception as e:
        logger.error("%s<error logging mop: %s>", indent, e, exc_info=True)
