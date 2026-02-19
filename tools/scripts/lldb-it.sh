#!/bin/bash
#
# Usage: lldb-it.sh <search_pattern> <file>
# Example:
#   ./lldb-it.sh 'static PyObject \*__pyx_f_.*?_fast_ast_fast_minsn_to_ast.*?\)\s*\{' _fast_ast.cpp
#
#   IDA_PROC_NAME       (default: ida)
#   SYMBOL_SEARCH_ROOT  (default: ./src/d810)
#
# This script finds a running IDA process, locates the first occurrence of a pattern in C/C++ source files,
# calculates the line number, and attaches LLDB with a breakpoint on the specified file and line.
#

set -euo pipefail

usage() {
    echo "Usage: $0 <search_pattern> <file>"
    echo "Example: $0 'static PyObject \*__pyx_f_.*?_fast_ast_fast_minsn_to_ast.*?\\)\\s*\\{' _fast_ast.cpp"
    echo "Environment:"
    echo "  IDA_PROC_NAME       (default: ida)"
    echo "  SYMBOL_SEARCH_ROOT  (default: ./src/d810)"
}

if [ $# -lt 2 ]; then
    usage
    exit 1
fi

SEARCH_PATTERN="$1"
BREAK_FILE="$2"
IDA_PROC_NAME="${IDA_PROC_NAME:-ida}"
SYMBOL_SEARCH_ROOT="${SYMBOL_SEARCH_ROOT:-./src/d810}"

if [ ! -f "$SYMBOL_SEARCH_ROOT/$BREAK_FILE" ] && [ ! -f "$BREAK_FILE" ]; then
    echo "Warning: file $BREAK_FILE not found in $SYMBOL_SEARCH_ROOT or current directory (continuing anyway, used only for LLDB breakpoint)"
fi

OSNAME=$(uname)
case "$OSNAME" in
    Darwin|Linux)
        PIDS=$(pgrep -x "$IDA_PROC_NAME" || true)
        ;;
    *)
        echo "Unsupported OS: $OSNAME"
        exit 1
        ;;
esac

if [ -z "$PIDS" ]; then
    echo "Error: IDA process not found (looked for process name: $IDA_PROC_NAME)"
    exit 1
fi

IDA_PID=$(echo "$PIDS" | head -n1)
echo "Found IDA process: $IDA_PID"

LINE_NUM=$(rg -n "$SEARCH_PATTERN" -i --glob '*.{c,cpp,cxx}' --no-heading "$SYMBOL_SEARCH_ROOT" | head -n1 | awk -F':' '{print $2}')
if [ -z "$LINE_NUM" ]; then
    echo "Error: Could not find target function with pattern: $SEARCH_PATTERN"
    exit 1
fi
echo "Found function at line: $LINE_NUM"

TMP_SYMBOLS_FILE=$(mktemp /tmp/lldb_symbols.XXXXXX.txt)

if [ "$OSNAME" == "Darwin" ]; then
    # On macOS, add all .dSYM bundles below SYMBOL_SEARCH_ROOT for debug symbols
    if command -v fd &> /dev/null; then
        SYMBOL_FILES=$(fd -u --type d '.dSYM$' "$SYMBOL_SEARCH_ROOT" || true)
    else
        SYMBOL_FILES=$(find "$SYMBOL_SEARCH_ROOT" -type d -name '*.dSYM' 2>/dev/null || true)
    fi
    if [ -n "$SYMBOL_FILES" ]; then
        while IFS= read -r line; do
            CLEANED_LINE="${line%/}"
            echo "target symbols add \"$CLEANED_LINE\""
        done <<< "$SYMBOL_FILES" > "$TMP_SYMBOLS_FILE"
    fi
else
    # On Linux, load all ELF binary/shared object files below SYMBOL_SEARCH_ROOT
    if command -v fd &> /dev/null; then
        SYMBOL_FILES=$(fd -u .so "$SYMBOL_SEARCH_ROOT" || true)
        # Also index unstripped ELF binaries without extensions
        ELF_FILES=$(fd -u "" "$SYMBOL_SEARCH_ROOT" --type f -x file --mime {} | grep 'application/x-executable\|application/x-sharedlib' | cut -d: -f1 || true)
        [ -n "$ELF_FILES" ] && SYMBOL_FILES="$SYMBOL_FILES"$'\n'"$ELF_FILES"
    else
        SYMBOL_FILES=$(find "$SYMBOL_SEARCH_ROOT" -type f \( -name '*.so' -o -perm -111 \) 2>/dev/null || true)
    fi
    if [ -n "$SYMBOL_FILES" ]; then
        while IFS= read -r line; do
            CLEANED_LINE="${line%/}"
            # On Linux, 'target symbols add' is a valid lldb command for ELF files
            echo "target symbols add \"$CLEANED_LINE\""
        done <<< "$SYMBOL_FILES" > "$TMP_SYMBOLS_FILE"
    fi
fi

TMP_LLDB_CMD_FILE=$(mktemp /tmp/lldb_commands.XXXXXX.txt)
cat > "$TMP_LLDB_CMD_FILE" <<EOF
breakpoint set --file $BREAK_FILE --line ${LINE_NUM}
$(cat "$TMP_SYMBOLS_FILE" 2>/dev/null || true)
breakpoint list
target list
continue
EOF

rm -f "$TMP_SYMBOLS_FILE"

lldb -p "$IDA_PID" -s "$TMP_LLDB_CMD_FILE"

rm -f "$TMP_LLDB_CMD_FILE"
rm -f /tmp/lldb_commands.txt