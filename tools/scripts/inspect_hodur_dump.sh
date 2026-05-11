#!/usr/bin/env bash
# Compatibility deprecation stub.
#
# Migrated to ./tools/cff_debug.py inspect -- see
# docs/debug-tooling-migration.md. This script forwards to the new command
# with positional-to-flag argument translation so existing callers like
#
#     ./tools/scripts/inspect_hodur_dump.sh .tmp/OUTPUT.txt
#
# still work.

set -euo pipefail

DUMP_FILE="${1:-.tmp/output.txt}"
echo "[deprecated] inspect_hodur_dump.sh migrated to cff_debug.py inspect;" >&2
echo "             forwarding to: ./tools/cff_debug.py inspect --dump ${DUMP_FILE}" >&2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/../cff_debug.py" inspect --dump "${DUMP_FILE}"
