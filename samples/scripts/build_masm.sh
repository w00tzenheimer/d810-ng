#!/usr/bin/env bash
# Build libobfuscated.dll with functions supplied as hand-assembled MASM
# (src/masm/<name>.asm, auto-discovered) instead of compiled C.
#
# MASM objects are MSVC-COFF, so the WHOLE build uses the MSVC ABI:
#   C   -> clang --target=x86_64-pc-windows-msvc
#   ASM -> llvm-ml64 (or ml64 on Windows)
#   LINK-> lld-link  (or link.exe on Windows)
# This is independent of the MinGW/Docker path used by `make` (which cannot
# cleanly link MSVC-COFF). Run from the samples/ directory or via `make masm`.
#
# Env knobs:
#   MASM_FUNCS   space-separated function base names (required)
#   BINARY_NAME  output stem (default: libobfuscated)
#   CC / ML64 / LINKER  toolchain overrides
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SAMPLES_DIR"

MASM_FUNCS="${MASM_FUNCS:-}"
BINARY_NAME="${BINARY_NAME:-libobfuscated}"
LLVM_BIN="$(brew --prefix llvm 2>/dev/null)/bin"

# Resolve a tool: honor an executable path / on-PATH name, else look in LLVM_BIN.
resolve_tool() {
    local t="$1"
    if [ -x "$t" ] || command -v "$t" >/dev/null 2>&1; then echo "$t"; return 0; fi
    if [ -x "${LLVM_BIN}/$(basename "$t")" ]; then echo "${LLVM_BIN}/$(basename "$t")"; return 0; fi
    return 1
}

CC="$(resolve_tool "${CC:-clang}")"          || { echo "error: clang not found" >&2; exit 1; }
ML64="$(resolve_tool "${ML64:-llvm-ml64}")"  || { echo "error: llvm-ml64/ml64 not found" >&2; exit 1; }
LINKER="$(resolve_tool "${LINKER:-lld-link}")" || { echo "error: lld-link not found" >&2; exit 1; }

# Default to every src/masm/*.asm (auto-discovery); MASM_FUNCS may override a subset.
if [ -z "$MASM_FUNCS" ]; then
    MASM_FUNCS="$(for a in src/masm/*.asm; do [ -e "$a" ] && basename "$a" .asm; done | tr '\n' ' ')"
fi
if [ -z "$(echo "$MASM_FUNCS" | tr -d ' ')" ]; then
    echo "error: no src/masm/*.asm files found (and MASM_FUNCS empty)" >&2
    exit 2
fi

BUILD_DIR="$SAMPLES_DIR/.build_masm"
rm -rf "$BUILD_DIR"; mkdir -p "$BUILD_DIR" bins

CFLAGS=(--target=x86_64-pc-windows-msvc -c -O0 -g -Iinclude -ffreestanding
        -fms-compatibility -fms-extensions -Wno-error -DD810_DLL_EXPORT=1)

# --- exclude the C bodies the asm replaces ---------------------------------
declare -A IS_MASM
for f in $MASM_FUNCS; do IS_MASM["$f"]=1; done

objs=()
compiled=0 skipped=0
for c in src/c/*.c; do
    base="$(basename "$c" .c)"
    [ -n "${IS_MASM[$base]:-}" ] && continue
    obj="$BUILD_DIR/$base.obj"
    if "$CC" "${CFLAGS[@]}" "$c" -o "$obj" 2>"$BUILD_DIR/$base.log"; then
        objs+=("$obj"); compiled=$((compiled + 1))
    else
        echo "  warn: skipping $base ($(head -1 "$BUILD_DIR/$base.log" | cut -c1-80))" >&2
        skipped=$((skipped + 1))
    fi
done
echo "C objects: compiled=$compiled skipped=$skipped"

# --- assemble the MASM functions -------------------------------------------
export_flags=()
for f in $MASM_FUNCS; do
    # src/masm/<f>.asm must be compilable MASM from the in-IDA "Export disassembly
    # -> MASM" action (materialized data + relocatable symbols).
    src="src/masm/$f.asm"
    [ -f "$src" ] || { echo "error: missing $src" >&2; exit 1; }
    obj="$BUILD_DIR/$f.obj"
    "$ML64" /nologo /c /Fo"$obj" "$src" >"$BUILD_DIR/$f.asm.log" 2>&1 \
        || { echo "error: assembling $f.asm failed:" >&2; cat "$BUILD_DIR/$f.asm.log" >&2; exit 1; }
    objs+=("$obj")
    export_flags+=("/EXPORT:$f")
    echo "  assembled $f.asm"
done

# --- link the DLL -----------------------------------------------------------
# Unresolved externs (inter-sample calls, the 3 sub_* targets) are expected and
# tolerated via /FORCE:UNRESOLVED; keep the noise in a log and just summarize.
out="bins/$BINARY_NAME.dll"
linklog="$BUILD_DIR/link.log"
"$LINKER" /DLL /NOENTRY /FORCE:UNRESOLVED "${export_flags[@]}" \
    "/OUT:$out" "${objs[@]}" 2>"$linklog" || true
undef=$(grep -c "undefined symbol" "$linklog" 2>/dev/null || echo 0)
[ -s "$out" ] || { echo "error: link failed:" >&2; cat "$linklog" >&2; exit 1; }
echo "linked $out  (${undef} unresolved externs tolerated; log: $linklog)"
file "$out" 2>/dev/null || true
echo "exported MASM funcs:"
for f in $MASM_FUNCS; do
    "${LLVM_BIN}/llvm-objdump" -p "$out" 2>/dev/null | grep -A500 "Export Table" | grep -qw "$f" \
        && echo "  ok: $f" || echo "  MISSING export: $f"
done
