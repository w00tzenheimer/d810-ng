"""Structural x64 MASM generator for a single function.

Drives off IDA's decoded ``insn_t``/``op_t`` (not the text listing): dispatches
on operand type, resolves immediates/displacements to **relocatable symbols**
via ``calc_reference_data``, and emits native MASM data definitions for the
referenced data closure. Output targets MSVC ``ml64`` (64-bit; no ``.MODEL``).

Design notes (grounded against real x64 ``op_t``):
* ``o_displ`` carries the *numeric* displacement in ``op.addr`` (IDA already
  resolved the frame variable), so no ``var_X=`` equates are needed.
* ``op.phrase`` is the base register only for simple ``[base+disp]`` forms; for
  SIB-with-index it is unreliable (REX extension is not reflected), so those
  operands are rendered via IDA's own operand formatter (always REX-correct).

Only the per-function entry point is public: :func:`generate_masm_for_function`.
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.ui.actions.export_disasm_logic import MasmPrinter, masm_sext64

logger = getLogger("D810.ui")

try:
    import ida_allins
    import ida_bytes
    import ida_funcs
    import ida_idp
    import ida_lines
    import ida_nalt
    import ida_name
    import ida_offset
    import ida_pro
    import ida_segment
    import ida_ua
    import idaapi
    import idautils
    import idc

    IDA_AVAILABLE = True
except ImportError:  # importable (inert) outside IDA, mirroring the Qt guard
    IDA_AVAILABLE = False

NATIVE_WIDTH = 8  # x64

# ida_ua.dt_* -> (masm size keyword, byte width)
_DT = {
    0: ("byte", 1),
    1: ("word", 2),
    2: ("dword", 4),
    3: ("dword", 4),   # float
    4: ("qword", 8),   # double
    5: ("tbyte", 10),
    7: ("qword", 8),
    8: ("xmmword", 16),
    11: ("fword", 6),
}


def _dt(dtype: int) -> tuple[str, int]:
    return _DT.get(dtype, ("qword", 8))


def _hexlit(value: int, force_sign: bool = False) -> str:
    """MASM hex literal via a throwaway printer (keeps sign/leading-0 rules)."""
    p = MasmPrinter()
    p.hex(value, force_sign=force_sign)
    return str(p)


class _FunctionMasmEmitter:
    """Emits one function (+ its referenced data/call closure) as ml64 MASM."""

    def __init__(self, func_ea: int) -> None:
        self.func = ida_funcs.get_func(func_ea)
        if self.func is None:
            raise ValueError(f"no function at {func_ea:#x}")
        self.start = self.func.start_ea
        self.end = self.func.end_ea
        self.image_base = idaapi.get_imagebase()
        self._names: dict[int, str] = {}
        self.proc_externs: dict[str, int] = {}   # name -> ea (functions/imports)
        self.data_refs: dict[int, str] = {}      # ea -> name (to materialize)

    # -- symbol naming -----------------------------------------------------
    def sym_name(self, ea: int) -> str | None:
        if ea in self._names:
            return self._names[ea]
        name = ida_name.get_ea_name(ea, ida_name.GN_LOCAL)
        if not name:
            return None
        # Sanitize names ml64 cannot accept verbatim.
        if ":" in name or name[0].isdigit():
            name = f"sym_{ea:X}"
        self._names[ea] = name
        return name

    def _in_func(self, ea: int) -> bool:
        return self.start <= ea < self.end

    # -- reference resolution ---------------------------------------------
    def _calc_target(self, ea: int, ri, addr: int) -> int | None:
        target = ida_pro.ea_pointer()
        base = ida_pro.ea_pointer()
        if not ida_offset.calc_reference_data(target.cast(), base.cast(), ea, ri, addr):
            return None
        t = target.value()
        return None if t == idaapi.BADADDR else masm_sext64(t)

    def resolve(self, ea: int, value: int, op, force_addr: bool):
        """Return (symbol_name_or_None, residual_delta)."""
        value = masm_sext64(value)
        target = None
        oi = ida_nalt_opinfo(ea, op.n)
        ftype = _op_ftype(ea, op.n)
        if ftype == ida_bytes.FF_N_OFF and oi is not None:
            target = self._calc_target(ea, oi.ri, value)
        if force_addr and target is None:
            target = value
        if target is not None:
            head = ida_bytes.get_item_head(target)
            target = masm_sext64(head) if head != idaapi.BADADDR else None
        if target is not None:
            name = self.sym_name(target)
            if name is not None:
                self._record_symbol(target, name)
                return name, value - target
        return None, value

    def _record_symbol(self, ea: int, name: str) -> None:
        if self._in_func(ea):
            return  # internal label, emitted inline
        if ida_funcs.get_func(ea) is not None or _is_import(ea):
            self.proc_externs.setdefault(name, ea)
        else:
            self.data_refs.setdefault(ea, name)

    # -- operand emission --------------------------------------------------
    def emit_operand(self, insn, op, is_lea: bool) -> str | None:
        ty = op.type
        if ty == ida_ua.o_void or not op.shown():
            return None
        ea = insn.ea
        size_kw, size = _dt(op.dtype)

        if ty == ida_ua.o_reg:
            return ida_idp.get_reg_name(op.reg, size) or f"reg{op.reg}"

        if ty in (ida_ua.o_imm, ida_ua.o_near):
            raw = op.value if ty == ida_ua.o_imm else op.addr
            name, delta = self.resolve(ea, raw, op, force_addr=(ty == ida_ua.o_near))
            if name is not None:
                prefix = "offset " if ty == ida_ua.o_imm else ""
                return prefix + name + (_hexlit(delta, force_sign=True) if delta else "")
            return _hexlit(delta)

        if ty == ida_ua.o_mem:
            name, delta = self.resolve(ea, op.addr, op, force_addr=True)
            inner = (name or "") + (_hexlit(delta, force_sign=True) if (name and delta) else "")
            if name is None:
                inner = _hexlit(delta)
            if is_lea:
                # lea needs a memory operand: bare `lea ecx, 0` is invalid, so a
                # disp-only target is bracketed (`lea ecx, [0]`); a clean symbol
                # can stay unbracketed (`lea ecx, sym`, RIP-relative).
                return name if (name and not delta) else f"[{inner}]"
            return f"{size_kw} ptr [{inner}]"

        if ty in (ida_ua.o_displ, ida_ua.o_phrase):
            has_sib = op.specflag1 == 1
            sib_index = (op.specflag2 >> 3) & 7 if has_sib else 4
            if has_sib and sib_index != 4:
                # SIB with index -> REX-correct rendering from IDA. IDA's operand
                # text already carries its own `<size> ptr`, so don't double it.
                inner = ida_lines_tag_remove(idc.print_operand(ea, op.n) or "")
                if is_lea or "ptr" in inner:
                    return inner
                return f"{size_kw} ptr {inner}"
            base = ida_idp.get_reg_name(op.phrase, NATIVE_WIDTH) or f"reg{op.phrase}"
            disp = masm_sext64(op.addr) if ty == ida_ua.o_displ else 0
            body = f"[{base}{_hexlit(disp, force_sign=True) if disp else ''}]"
            return body if is_lea else f"{size_kw} ptr {body}"

        if ty == ida_ua.o_idpspec3:  # x87 st(i)
            return "st" if op.reg == 0 else f"st({op.reg})"

        # Unknown operand kind: fall back to IDA's renderer rather than guess.
        return ida_lines_tag_remove(idc.print_operand(ea, op.n) or "")

    def emit_insn(self, ea: int) -> MasmPrinter:
        p = MasmPrinter()
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, ea) <= 0:
            p.line(f"; <undecodable {ea:#x}>")
            return p
        mnem = insn.get_canon_mnem()
        aux = insn.auxpref
        if aux & 0x1:
            p.write("lock ")
        if aux & 0x2 and mnem not in ("retn",):
            p.write("repe " if mnem == "cmps" else "rep ")
        if aux & 0x4:
            p.write("repne ")
        p.write("ret" if mnem == "retn" else mnem)
        if mnem in ("movs", "scas", "stos", "cmps"):
            p.write({0: "b", 1: "w", 2: "d", 7: "q"}.get(insn.ops[0].dtype, ""))

        is_lea = insn.itype == ida_allins.NN_lea
        first = True
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            tok = self.emit_operand(insn, op, is_lea)
            if tok is None:
                continue
            p.write(" " if first else ", ")
            first = False
            p.write(tok)
        return p

    # -- data emission -----------------------------------------------------
    def emit_data(self, ea: int) -> MasmPrinter:
        p = MasmPrinter()
        flags = ida_bytes.get_full_flags(ea)
        size = ida_bytes.get_item_size(ea)
        dtype = flags & (ida_bytes.DT_TYPE & 0xFFFFFFFF)
        raw = ida_bytes.get_bytes(ea, size) or b""

        if dtype == (ida_bytes.FF_STRLIT & 0xFFFFFFFF):
            p.write_bytes(raw, 0, len(raw))
            return p

        scalar = {
            (ida_bytes.FF_BYTE & 0xFFFFFFFF): ("db", 1),
            (ida_bytes.FF_WORD & 0xFFFFFFFF): ("dw", 2),
            (ida_bytes.FF_DWORD & 0xFFFFFFFF): ("dd", 4),
            (ida_bytes.FF_QWORD & 0xFFFFFFFF): ("dq", 8),
            (ida_bytes.FF_TBYTE & 0xFFFFFFFF): ("dt", 10),
        }
        if dtype in scalar and size:
            directive, width = scalar[dtype]
            n = size // width if width else 0
            for i in range(n):
                if i:
                    p.line()
                chunk = raw[i * width:(i + 1) * width]
                p.write(f"{directive} ")
                if width == 8 and dtype == (ida_bytes.FF_QWORD & 0xFFFFFFFF):
                    # A qword may be a relocatable pointer; resolve it.
                    val = int.from_bytes(chunk, "little")
                    name = self.sym_name(ida_bytes.get_item_head(val)) if val else None
                    if name is not None and ida_bytes.get_item_head(val) == val:
                        self._record_symbol(val, name)
                        p.write(name)
                        continue
                p.hex(int.from_bytes(chunk, "little"))
            return p

        # Fallback: raw bytes (vectors, structs, aggregates -> portable db runs).
        p.write_bytes(raw, 0, len(raw))
        return p

    # -- driver ------------------------------------------------------------
    def collect_body(self) -> MasmPrinter:
        body = MasmPrinter()
        for ea in idautils.Heads(self.start, self.end):
            flags = ida_bytes.get_full_flags(ea)
            if ea != self.start and ida_bytes.has_any_name(flags):
                name = self.sym_name(ea)
                if name:
                    body.line(f"{name}:")
            if ida_bytes.is_code(flags):
                body.extend(self.emit_insn(ea))
                body.line()
            elif ida_bytes.is_align(flags):
                continue  # alignment padding is irrelevant for analysis
        return body

    def generate(
        self, materialize_data: bool = True, const_data: bool = False
    ) -> str:
        fname = self.sym_name(self.start) or f"sub_{self.start:X}"
        body = self.collect_body()  # populates proc_externs / data_refs

        out = MasmPrinter()
        out.line("; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64")
        out.line(f"; Function: {fname}  @ {self.start:#x}")
        out.line("OPTION PROLOGUE:NONE")
        out.line("OPTION EPILOGUE:NONE")
        out.line()
        for name in sorted(self.proc_externs):
            out.line(f"EXTERN {name}:PROC")

        unresolved: list[str] = []
        data_lines = MasmPrinter()
        for ea in sorted(self.data_refs):
            name = self.data_refs[ea]
            if not materialize_data:
                unresolved.append(name)
                continue
            try:
                d = self.emit_data(ea)
            except Exception as exc:  # noqa: BLE001
                logger.debug("data %s @ %#x not materialized: %s", name, ea, exc)
                unresolved.append(name)
                continue
            # Put the symbol directly on the first data line ("name db ...");
            # ml64's `LABEL` directive form is less portable across assemblers.
            data_lines.write(f"{name} ")
            data_lines.extend(d)
            data_lines.line()
        for name in unresolved:
            out.line(f"EXTERN {name}:BYTE")

        if str(data_lines):
            # const_data -> a read-only segment named `.rdata` (READONLY + class
            # 'CONST'); otherwise the writable `_DATA`. Both assemble under
            # ml64/llvm-ml64 and the `.rdata` name lands in the PE's .rdata.
            if const_data:
                seg = ".rdata"
                header = ".rdata SEGMENT READONLY ALIGN(16) 'CONST'"
            else:
                seg = "_DATA"
                header = "_DATA SEGMENT"
            out.line()
            out.line(header)
            out.extend(data_lines)
            out.line(f"{seg} ENDS")

        out.line()
        out.line("_TEXT SEGMENT ALIGN(16) 'CODE'")
        out.line(f"PUBLIC {fname}")
        out.line(f"{fname}:")
        out.indent(4)
        out.extend(body)
        out.indent(-4)
        out.line("_TEXT ENDS")
        out.line("END")
        return str(out)


# -- small module-level helpers (kept here so the logic module stays IDA-free) --
def ida_nalt_opinfo(ea: int, n: int):
    oi = ida_nalt.opinfo_t()
    flags = ida_bytes.get_full_flags(ea)
    return oi if ida_bytes.get_opinfo(oi, ea, n, flags) else None


def _op_ftype(ea: int, n: int) -> int:
    flags = ida_bytes.get_full_flags(ea)
    return (flags >> ida_bytes.get_operand_type_shift(n)) & ida_bytes.MS_N_TYPE


def _is_import(ea: int) -> bool:
    seg = ida_segment.getseg(ea)
    return bool(seg) and seg.type == ida_segment.SEG_XTRN


def ida_lines_tag_remove(text: str) -> str:
    return ida_lines.tag_remove(text) if text else ""


def generate_masm_for_function(
    func_ea: int, materialize_data: bool = True, const_data: bool = False
) -> str:
    """Generate compilable x64 ml64 MASM for the function at ``func_ea``.

    Raises RuntimeError if called outside IDA. The result includes the function
    body, its referenced data closure (materialized) and call externs. When
    ``const_data`` is set, the materialized data goes in a read-only ``CONST``
    segment (.rdata) instead of the writable ``_DATA`` segment.
    """
    if not IDA_AVAILABLE:
        raise RuntimeError("generate_masm_for_function requires IDA Pro")
    return _FunctionMasmEmitter(func_ea).generate(
        materialize_data=materialize_data, const_data=const_data
    )
