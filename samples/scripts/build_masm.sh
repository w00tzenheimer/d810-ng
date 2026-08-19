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

verify_required_exports() {
    local export_dump="$1"
    shift
    local export_names
    local symbol
    local missing=0

    export_names="$(awk '
        /^Export Table:$/ { in_exports = 1; next }
        in_exports && /^[[:alpha:]][^:]*Table:$/ { in_exports = 0 }
        in_exports && $1 ~ /^[0-9]+$/ && $2 ~ /^0x[0-9A-Fa-f]+$/ { print $3 }
    ' "$export_dump")"
    for symbol in "$@"; do
        if printf '%s\n' "$export_names" | grep -Fxq -- "$symbol"; then
            echo "  ok: $symbol"
        else
            echo "error: MISSING required MASM export: $symbol" >&2
            missing=1
        fi
    done
    return "$missing"
}

explicit_d810_exports() {
    sed -nE 's/^[[:space:]]*;[[:space:]]*D810_EXPORT[[:space:]]+([A-Za-z0-9_]+)[[:space:]]*$/\1/p' "$1"
}

callsite_marker_exports() {
    sed -nE 's/^[[:space:]]*PUBLIC[[:space:]]+(d810_callsite_[A-Za-z0-9_]+)[[:space:]]*$/\1/p' "$1"
}

# Narrow test seam for the post-link contract.  The normal build writes the
# real llvm-objdump output and derives required names with the same directive
# parser below.
if [ "${1:-}" = "--verify-source-exports" ]; then
    [ "$#" -eq 4 ] || {
        echo "usage: $0 --verify-source-exports <objdump-output> <basename> <asm-source>" >&2
        exit 2
    }
    export_dump="$2"
    basename="$3"
    asm_source="$4"
    required=("$basename")
    for symbol in $(explicit_d810_exports "$asm_source"); do
        required+=("$symbol")
    done
    for symbol in $(callsite_marker_exports "$asm_source"); do
        required+=("$symbol")
    done
    verify_required_exports "$export_dump" "${required[@]}"
    exit $?
fi

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
required_exports=()
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
    required_exports+=("$f")
    # A source may contain additional fixture anchors.  They must opt in with
    # an explicit ``; D810_EXPORT <symbol>`` directive; exporting every PUBLIC
    # symbol would leak unrelated data/labels from large MASM exports.
    public_names="$(explicit_d810_exports "$src")"
    for public_name in $public_names; do
        export_flags+=("/EXPORT:$public_name")
        required_exports+=("$public_name")
    done
    # Explicit call-site markers are source-to-native oracle anchors.  Export
    # only the opt-in PUBLIC labels rather than guessing from imported call
    # targets, which may be linked as generic unresolved slots in the fixture.
    marker_names="$(callsite_marker_exports "$src")"
    for marker in $marker_names; do
        export_flags+=("/EXPORT:$marker")
        required_exports+=("$marker")
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
export_dump="$BUILD_DIR/export_table.txt"
"${LLVM_BIN}/llvm-objdump" -p "$out" >"$export_dump" 2>/dev/null \
    || { echo "error: failed to inspect exports in $out" >&2; exit 1; }
echo "required MASM exports:"
verify_required_exports "$export_dump" "${required_exports[@]}"
