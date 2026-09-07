"""Trusted SWIG pointer identity, resolved only after native runtime entry."""

from functools import cache

import ida_hexrays


@cache
def swig_pointer_type() -> type:
    """Obtain the actual vendor-produced type without trusting a class name.

    An empty mop is safe only after Hex-Rays is initialized. Callers must
    already have checked that their operand is a live vendor wrapper.
    """
    return type(ida_hexrays.mop_t().this)
