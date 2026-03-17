#!/usr/bin/env bash
# Inspect a Hodur dump file for key diagnostics.
# Usage: ./tools/scripts/inspect_hodur_dump.sh .tmp/OUTPUT.txt

FILE="${1:-.tmp/output.txt}"

echo "=== Gate Failures ==="
rg -C3 'Gate accounting: \d+ passed, [1-9]\d* failed, \d+ bypassed' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Provenance ==="
rg 'Provenance:' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== PruneUnreachable ==="
rg 'PruneUnreachable:' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Metrics ==="
rg '^(BEFORE|AFTER|DELTA):' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== INTERR ==="
rg -i 'INTERR|50860|50858|50856' "$FILE" 2>/dev/null | grep -v invariants | head -5 || echo "(none)"

echo ""
echo "=== Rejected Stages ==="
rg 'rejected stage' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Valrange Probe ==="
rg 'VALRANGE_PROBE' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== POST-APPLY ==="
rg 'POST-APPLY' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== verify_failed ==="
rg -i 'verify_failed' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Return Frontier ==="
rg 'RETURN_FRONTIER' "$FILE" 2>/dev/null || echo "(none)"
