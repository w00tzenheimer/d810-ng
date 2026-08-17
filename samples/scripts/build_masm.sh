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
#   selector     optional positional selector: unflattening_effect_safety
#   MASM_FUNCS   space-separated function base names (auto-discovered by default)
#   BINARY_NAME  output stem (default: libobfuscated)
#   CC / ML64 / LINKER  toolchain overrides
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SAMPLES_DIR"

SELECTOR="${1:-}"
if [ "$#" -gt 1 ]; then
    echo "error: expected at most one build target selector" >&2
    exit 2
fi
MASM_FUNCS="${MASM_FUNCS:-}"
BINARY_NAME="${BINARY_NAME:-}"

case "$SELECTOR" in
    "")
        BINARY_NAME="${BINARY_NAME:-libobfuscated}"
        ;;
    unflattening_effect_safety)
        MASM_FUNCS="${MASM_FUNCS:-sub_7FF8569F0540 sub_7FF8568132D0 sub_7FF855576B50}"
        BINARY_NAME="${BINARY_NAME:-unflattening_effect_safety}"
        ;;
    *)
        echo "error: unsupported build target selector: $SELECTOR" >&2
        exit 2
        ;;
esac
LLVM_PREFIX="$(brew --prefix llvm 2>/dev/null || true)"
LLVM_BIN="${LLVM_PREFIX:+$LLVM_PREFIX/bin}"

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
OBJDUMP="$(resolve_tool "${LLVM_OBJDUMP:-llvm-objdump}")" || {
    echo "error: llvm-objdump/objdump not found" >&2
    exit 1
}

# Default to every src/masm/*.asm (auto-discovery); MASM_FUNCS may override a subset.
if [ -z "$MASM_FUNCS" ]; then
    MASM_FUNCS="$(for a in src/masm/*.asm; do [ -e "$a" ] && basename "$a" .asm; done | tr '\n' ' ')"
fi
if [ -z "$(echo "$MASM_FUNCS" | tr -d ' ')" ]; then
    echo "error: no src/masm/*.asm files found (and MASM_FUNCS empty)" >&2
    exit 2
fi

BUILD_DIR=".build_masm"
rm -rf "$BUILD_DIR"; mkdir -p "$BUILD_DIR" bins

CFLAGS=(--target=x86_64-pc-windows-msvc -c -O0 -g -Iinclude -ffreestanding
        -fms-compatibility -fms-extensions -Wno-error -DD810_DLL_EXPORT=1
        "-fdebug-prefix-map=$SAMPLES_DIR=/src/d810/samples")

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
callsite_markers=()
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
    # Explicit call-site markers are source-to-native oracle anchors.  Export
    # only the opt-in PUBLIC labels rather than guessing from imported call
    # targets, which may be linked as generic unresolved slots in the fixture.
    marker_names="$(sed -nE 's/^[[:space:]]*PUBLIC[[:space:]]+(d810_callsite_[A-Za-z0-9_]+)[[:space:]]*$/\1/p' "$src")"
    for marker in $marker_names; do
        export_flags+=("/EXPORT:$marker")
        callsite_markers+=("$marker")
        echo "  exported callsite marker $marker"
    done
    echo "  assembled $f.asm"
done

# --- link the DLL -----------------------------------------------------------
# Unresolved externs (inter-sample calls, the 3 sub_* targets) are expected and
# tolerated via /FORCE:UNRESOLVED; keep the noise in a log and just summarize.
out="bins/$BINARY_NAME.dll"
pdb="bins/$BINARY_NAME.pdb"
linklog="$BUILD_DIR/link.log"
"$LINKER" /DLL /NOENTRY /DEBUG /FORCE:UNRESOLVED "${export_flags[@]}" \
    "/OUT:$out" "/PDB:$pdb" "/PDBALTPATH:$BINARY_NAME.pdb" \
    /PDBSOURCEPATH:/src/d810/samples "${objs[@]}" 2>"$linklog" || true
undef=$(grep -c "undefined symbol" "$linklog" 2>/dev/null || echo 0)
[ -s "$out" ] || { echo "error: link failed:" >&2; cat "$linklog" >&2; exit 1; }
[ -s "$pdb" ] || { echo "error: linker did not produce $pdb" >&2; exit 1; }
echo "linked $out and $pdb  (${undef} unresolved externs tolerated; log: $linklog)"
file "$out" 2>/dev/null || true
echo "exported MASM funcs:"
for f in $MASM_FUNCS; do
    "$OBJDUMP" -p "$out" 2>/dev/null | grep -A500 "Export Table" | grep -qw "$f" \
        && echo "  ok: $f" \
        || { echo "error: MISSING export: $f" >&2; exit 1; }
done
expected_markers=()
if [ "$SELECTOR" = "unflattening_effect_safety" ]; then
    expected_markers=(
        d810_callsite_sub_7FF8569F0540_memcpy
        d810_callsite_sub_7FF8568132D0_srw_lock
        d810_callsite_sub_7FF855576B50_message_box
        d810_callsite_sub_7FF855576B50_get_current_process
        d810_callsite_sub_7FF855576B50_terminate_process
    )
fi
for expected in "${expected_markers[@]}"; do
    case " ${callsite_markers[*]} " in
        *" $expected "*) ;;
        *)
            echo "error: missing required callsite marker in source: $expected" >&2
            exit 1
            ;;
    esac
done
for marker in "${callsite_markers[@]}"; do
    "$OBJDUMP" -p "$out" 2>/dev/null | grep -A500 "Export Table" | grep -qw "$marker" \
        || { echo "error: MISSING callsite marker export: $marker" >&2; exit 1; }
    echo "  ok: $marker"
done
