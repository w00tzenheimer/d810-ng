"""Answer "is this loaded global's value USED as an address?" from microcode.

WHY THIS SHAPE, from the microcode IDA actually emits at MMAT_GLBOPT1 for the
motivating function::

    sub ((($dword_7FF85AAE4464.4{141} - #0x225A557) | #0x97506C0B) + ...), .., edx.4{152}
    xor edx.4{152}, #0xAF863FED, r9d.4{154}
    ...
    mov call $MapViewOfFile<.., "DWORD dwDesiredAccess" (...), ..>

Three measured facts drive the design:

* The MBA is ONE nested expression tree inside a single instruction. Its
  intermediates never occupy a register or stack slot, so a value-range query
  (``get_valranges`` takes a ``vivl_t``, i.e. a named location) has no subject
  and returns nothing. Value-set analysis is the wrong tool here.
* Cross-instruction hops are few and go through registers carrying SSA valnums
  (``{152}``, ``{154}``). Keying on ``(reg, size, valnum)`` is what stops a
  register-name walk from leaking into unrelated reads of the same register
  elsewhere in the function.
* The discriminator is DEREFERENCE, not ``lea``: obfuscators emit ``lea`` as a
  no-flags add. A value is used as an address only when it reaches the ADDRESS
  operand of ``m_ldx``/``m_stx``.

Because the test is structural containment rather than value comparison, it also
catches the RVA shape (``imagebase + value`` then dereference): the global leaf
still sits inside the address operand's subtree whatever arithmetic wraps it.

READ-ONLY with respect to the microcode. The fixpoint is kept free of Hex-Rays
types so it can be tested directly; only the ``_Hexrays*`` layer touches the SDK.
"""

from __future__ import annotations

from d810.core import logging
from d810.core import typing

logger = logging.getLogger(__name__)

#: Bound on propagation rounds. Each round can only add carriers, so the
#: fixpoint converges quickly in practice; exceeding it yields ``None``
#: (unknown), never a guess.
DEFAULT_MAX_ROUNDS = 32


class CarrierGraph(typing.Protocol):
    """The four questions the fixpoint asks about the microcode."""

    def instructions(self) -> typing.Iterable[typing.Any]:
        """Every instruction in the function."""

    def address_carriers(self, insn: typing.Any) -> frozenset[typing.Any] | None:
        """Carrier keys inside *insn*'s dereference ADDRESS operand.

        ``None`` when *insn* is not a dereference at all, which is different
        from an empty set (a dereference whose address holds no carrier).
        """

    def source_carriers(self, insn: typing.Any) -> frozenset[typing.Any]:
        """Carrier keys appearing anywhere in *insn*'s source operands."""

    def defined_carrier(self, insn: typing.Any) -> typing.Any | None:
        """The carrier key *insn* defines, or ``None`` if it defines no key."""


def carrier_reaches_dereference(
    graph: CarrierGraph,
    initial: typing.Iterable[typing.Any],
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
) -> bool | None:
    """Does any *initial* carrier reach a dereference address operand?

    Returns ``True`` when some carrier appears in a dereference's address
    operand, ``False`` when the carrier set reaches a fixpoint without that
    happening, and ``None`` when the question could not be answered -- the
    microcode was unwalkable, there was nothing to start from, or propagation
    did not converge inside *max_rounds*. ``None`` means "unknown"; callers must
    not read it as either answer.
    """

    carriers = set(initial)
    if not carriers:
        logger.debug("dereference trace: no initial carrier; unknown")
        return None

    for _ in range(max_rounds):
        try:
            instructions = tuple(graph.instructions())
        except Exception:
            logger.debug("dereference trace: microcode unwalkable", exc_info=True)
            return None

        discovered: set[typing.Any] = set()
        for insn in instructions:
            try:
                address = graph.address_carriers(insn)
                if address and (address & carriers):
                    return True
                if graph.source_carriers(insn) & carriers:
                    defined = graph.defined_carrier(insn)
                    if defined is not None and defined not in carriers:
                        discovered.add(defined)
            except Exception:
                logger.debug(
                    "dereference trace: instruction walk failed", exc_info=True
                )
                return None

        if not discovered:
            return False
        carriers |= discovered

    logger.debug(
        "dereference trace: no fixpoint in %d rounds (%d carriers); unknown",
        max_rounds,
        len(carriers),
    )
    return None


def value_reaches_dereference(
    blk: typing.Any,
    ins: typing.Any,
    *,
    address: int | None = None,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
) -> bool | None:
    """Live-microcode entry point. ``None`` whenever the answer is not provable.

    *address* is the global whose loaded value is in question; it seeds the
    carrier set as the global leaf that appears in the operand trees.
    """

    try:
        import ida_hexrays  # noqa: PLC0415  (SDK import is deliberately lazy)
    except ImportError:
        return None

    if address is None:
        return None

    mba = getattr(blk, "mba", None)
    if mba is None:
        logger.debug("dereference trace: no mba on block; unknown")
        return None

    # SSA valnums are what separate this definition from unrelated reads of the
    # same register. IDA assigns them at MMAT_GLBOPT1; earlier every operand
    # carries valnum 0, so all definitions of a register collapse to one key and
    # the fixpoint leaks into unrelated code -- reporting a dereference that is
    # not on this chain. Refuse to answer where the key cannot discriminate.
    maturity = getattr(mba, "maturity", None)
    if maturity is None or int(maturity) < int(ida_hexrays.MMAT_GLBOPT1):
        if logger.debug_on:
            logger.debug(
                "dereference trace: maturity %s is below GLBOPT1, "
                "no SSA valnums; unknown",
                maturity,
            )
        return None

    graph = _HexraysCarrierGraph(mba, ida_hexrays)
    return carrier_reaches_dereference(
        graph, {("global", int(address))}, max_rounds=max_rounds
    )


class _HexraysCarrierGraph:
    """:class:`CarrierGraph` over a live ``mba_t``."""

    def __init__(self, mba: typing.Any, sdk: typing.Any) -> None:
        self._mba = mba
        self._sdk = sdk

    def instructions(self) -> typing.Iterator[typing.Any]:
        for index in range(self._mba.qty):
            insn = self._mba.get_mblock(index).head
            while insn:
                yield insn
                insn = insn.next

    def address_carriers(self, insn: typing.Any) -> frozenset[typing.Any] | None:
        sdk = self._sdk
        opcode = getattr(insn, "opcode", None)
        if opcode == sdk.m_ldx:
            operand = getattr(insn, "r", None)
        elif opcode == sdk.m_stx:
            # m_stx stores value `l` at address `d`.
            operand = getattr(insn, "d", None)
        else:
            return None
        return _carrier_keys(operand, sdk)

    def source_carriers(self, insn: typing.Any) -> frozenset[typing.Any]:
        sdk = self._sdk
        return _carrier_keys(getattr(insn, "l", None), sdk) | _carrier_keys(
            getattr(insn, "r", None), sdk
        )

    def defined_carrier(self, insn: typing.Any) -> typing.Any | None:
        sdk = self._sdk
        if getattr(insn, "opcode", None) == sdk.m_stx:
            # `d` is an address, not a defined value.
            return None
        dest = getattr(insn, "d", None)
        if dest is None or getattr(dest, "t", None) != sdk.mop_r:
            return None
        return _register_carrier(dest)


def _register_carrier(mop: typing.Any) -> tuple[str, int, int, int | None]:
    """SSA-keyed identity for a register operand.

    ``valnum`` is what separates this definition from unrelated reads of the
    same register elsewhere in the function. When the SDK does not expose it the
    key degrades to the register name, which is imprecise but not silently so:
    the fixpoint may then report a dereference that is not on this chain, and a
    veto is the conservative outcome for this caller.
    """
    return ("reg", int(mop.r), int(mop.size), _valnum_of(mop))


def _valnum_of(mop: typing.Any) -> int | None:
    try:
        value = getattr(mop, "valnum", None)
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _carrier_keys(mop: typing.Any, sdk: typing.Any) -> frozenset[typing.Any]:
    """Every carrier key appearing anywhere inside *mop*, recursing into trees."""
    if mop is None:
        return frozenset()
    kind = getattr(mop, "t", None)
    if kind == sdk.mop_r:
        return frozenset({_register_carrier(mop)})
    if kind == sdk.mop_v:
        try:
            return frozenset({("global", int(mop.g))})
        except (AttributeError, TypeError, ValueError):
            return frozenset()
    if kind == sdk.mop_d and getattr(mop, "d", None) is not None:
        sub = mop.d
        return (
            _carrier_keys(getattr(sub, "l", None), sdk)
            | _carrier_keys(getattr(sub, "r", None), sdk)
            | _carrier_keys(getattr(sub, "d", None), sdk)
        )
    return frozenset()


__all__ = [
    "DEFAULT_MAX_ROUNDS",
    "CarrierGraph",
    "carrier_reaches_dereference",
    "value_reaches_dereference",
]
