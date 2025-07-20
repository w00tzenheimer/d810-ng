import functools
import logging
import os
import typing
from typing import List

import idaapi
from ida_hexrays import mbl_array_t, minsn_t, mop_t, vd_printer_t

from d810.hexrays.hexrays_helpers import (
    MATURITY_TO_STRING_DICT,
    MOP_TYPE_TO_STRING_DICT,
    OPCODES_INFO,
    STRING_TO_MATURITY_DICT,
)

logger = logging.getLogger("D810.helper")

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


def format_mop_list(mop_list: List[mop_t]) -> str:
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


def write_mc_to_file(mba: mbl_array_t, filename: str, mba_flags: int = 0) -> bool:
    if not mba:
        return False

    vp = mba_printer()
    mba.set_mba_flags(mba_flags)
    mba._print(vp)

    with open(filename, "w") as f:
        f.writelines(vp.get_mc())
    return True


def dump_microcode_for_debug(mba: mbl_array_t, log_dir_path: str, name: str = ""):
    mc_filename = os.path.join(
        log_dir_path,
        "{0:x}_maturity_{1}_{2}.log".format(mba.entry_ea, mba.maturity, name),
    )
    logger.info("Dumping microcode in file {0}...".format(mc_filename))
    write_mc_to_file(mba, mc_filename)


def sanitize_ea(ea: int | None) -> int | None:
    if ea is None:
        return None
    return ea & idaapi.BADADDR  # BADADDR = 0xFFFF_FFFF_FFFF_FFFF on x64
