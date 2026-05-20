#!/usr/bin/env bash
# Compatibility deprecation stub.
#
# Migrated to ./tools/d810cli.py inspect -- see
# docs/debug-tooling-migration.md. This script forwards to the new command
# with positional-to-flag argument translation so existing callers like
#
#     ./tools/scripts/inspect_hodur_dump.sh .tmp/OUTPUT.txt
#
# still work.

set -euo pipefail

DUMP_FILE="${1:-.tmp/output.txt}"
echo "[deprecated] inspect_hodur_dump.sh migrated to d810cli.py inspect;" >&2
echo "             forwarding to: ./tools/d810cli.py inspect --dump ${DUMP_FILE}" >&2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/../d810cli.py" inspect --dump "${DUMP_FILE}"
