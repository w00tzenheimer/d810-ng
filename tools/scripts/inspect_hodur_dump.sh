#!/usr/bin/env bash
# Inspect a Hodur dump file for key diagnostics.
# Usage: ./tools/scripts/inspect_hodur_dump.sh .tmp/OUTPUT.txt

FILE="${1:-.tmp/output.txt}"

echo "=== Gate Failures ==="
rg -A1 'Gate accounting: \d+ passed, [1-9]\d* failed, \d+ bypassed' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Provenance ==="
rg 'Provenance:' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== PruneUnreachable ==="
rg 'PruneUnreachable:' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Metrics ==="
rg '(BEFORE|AFTER|DELTA):.*lines=' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== INTERR ==="
rg 'INTERR' "$FILE" 2>/dev/null | head -20 || echo "(none)"

echo ""
echo "=== Serial Remap ==="
rg 'serial remap' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Transient Denylist ==="
rg 'transient (corridor entries|denylist)' "$FILE" 2>/dev/null | head -5 || echo "(none)"

echo ""
echo "=== Boundary Classifier ==="
rg 'supplemental classification' "$FILE" 2>/dev/null | sed 's/.*→ //' | sort | uniq -c | sort -rn || echo "(none)"

echo ""
echo "=== DSVE Guard ==="
rg 'DSVE guard (KEPT|OVERRIDDEN)' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== PTS Gate ==="
rg 'PTS gate' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Verify Failure Artifacts ==="
rg -o 'verify_failures/[^ ]*\.json' "$FILE" 2>/dev/null | sort -u | while read -r artifact; do
  # artifact is relative path like verify_failures/verify_fail_...json
  # try common base dirs
  for base in .tmp/logs/d810_logs /root/.idapro/logs/d810_logs ~/.idapro/logs/d810_logs; do
    full="$base/$artifact"
    if [ -f "$full" ]; then
      echo "--- $full ---"
      cat "$full"
      echo ""
      break
    fi
  done
done
if ! rg -q 'verify_failures/' "$FILE" 2>/dev/null; then
  echo "(none)"
fi

echo ""
echo "=== Rejected Stages ==="
rg 'rejected stage' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Applied Modifications ==="
rg 'Applied \d+/\d+ modifications' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Failed Modifications ==="
rg -B3 'RESULT: FAILED' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== RECON DAG ==="
rg 'RECON DAG: accepted' "$FILE" 2>/dev/null || echo "(none)"

echo ""
echo "=== Exceptions ==="
rg 'EXCEPTION|exception \d+|RuntimeError|RESULT: EXCEPTION' "$FILE" 2>/dev/null | head -10 || echo "(none)"

echo ""
echo "=== Decompile Status ==="
rg 'Failed to decompile|PASSED|FAILED.*test_dump' "$FILE" 2>/dev/null | tail -3 || echo "(none)"

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
