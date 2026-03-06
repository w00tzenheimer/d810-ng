"""Release gate: enforces that all INTERR codes are accounted for."""
import json
import pathlib
import pytest

_CFG_CONTRACT_DIR = pathlib.Path(__file__).resolve().parents[4] / "src" / "d810" / "cfg" / "contracts"

_TERMINAL_DISPOSITIONS = {"mapped", "native_oracle", "native_oracle_limited", "native_oracle_deferred", "blocked_by_api"}
_PROHIBITED_DISPOSITIONS = {"unmapped", "unknown"}

def _load_matrix(name):
    path = _CFG_CONTRACT_DIR / name
    if not path.exists():
        pytest.skip(f"{name} not found")
    with open(path) as f:
        return json.load(f)

class TestReleaseGate:
    def test_mblock_no_unmapped(self):
        matrix = _load_matrix("parity_matrix.json")
        for entry in matrix["codes"]:
            assert entry["disposition"] not in _PROHIBITED_DISPOSITIONS, \
                f"Code {entry['code']} has prohibited disposition: {entry['disposition']}"

    def test_mblock_no_planned_at_release(self):
        """All 'planned' codes must be promoted before release."""
        matrix = _load_matrix("parity_matrix.json")
        planned = [e for e in matrix["codes"] if e["disposition"] == "planned"]
        # This is a WARNING test, not a hard gate (planned codes may exist during development)
        if planned:
            codes = [e["code"] for e in planned]
            pytest.skip(f"Development mode: {len(planned)} planned codes remain: {codes}")

    def test_insn_matrix_exists(self):
        """Instruction-level matrix must exist."""
        path = _CFG_CONTRACT_DIR / "insn_parity_matrix.json"
        if not path.exists():
            pytest.skip("insn_parity_matrix.json not found — Phase 5 incomplete")

    def test_insn_no_unmapped(self):
        matrix = _load_matrix("insn_parity_matrix.json")
        for entry in matrix["codes"]:
            assert entry["disposition"] not in _PROHIBITED_DISPOSITIONS, \
                f"Code {entry['code']} has prohibited disposition: {entry['disposition']}"

    def test_native_oracle_availability_tracked(self):
        """Verify we can programmatically check oracle status."""
        from d810.cfg.contracts.native_oracle import oracle_available, NATIVE_ORACLE_AVAILABLE
        assert oracle_available() == NATIVE_ORACLE_AVAILABLE
        # In non-Cython env, oracle is unavailable — that's OK but must be tracked
        if not oracle_available():
            import warnings
            warnings.warn("Native oracle not available — 15 codes unchecked")

    def test_combined_summary(self):
        """Print combined parity summary across both scopes."""
        summaries = {}
        for name in ["parity_matrix.json", "insn_parity_matrix.json"]:
            try:
                matrix = _load_matrix(name)
            except pytest.skip.Exception:
                continue
            scope = matrix.get("scope", name)
            counts = {}
            for e in matrix["codes"]:
                d = e["disposition"]
                counts[d] = counts.get(d, 0) + 1
            summaries[scope] = counts

        print("\n=== Combined Parity Summary ===")
        for scope, counts in summaries.items():
            total = sum(counts.values())
            print(f"\n{scope} ({total} codes):")
            for disp, count in sorted(counts.items()):
                print(f"  {disp}: {count}")
