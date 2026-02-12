# Pattern Engine Baseline (PR0)

**Generated**: 2026-02-12 13:50:11

## Summary

| Benchmark | Metric | Value |
|-----------|--------|-------|
| hot_path | instruction_count | 100 |
| hot_path | throughput_insns_per_sec | 5056890.2078 |
| hot_path | us_per_instruction | 0.1977 |
| lookup_hit | candidate_count | 10 |
| lookup_hit | legacy_us_per_lookup | 4.4246 |
| lookup_hit | new_us_per_lookup | 6.3346 |
| lookup_hit | speedup | 0.6985 |
| lookup_miss | candidate_count | 10 |
| lookup_miss | legacy_us_per_lookup | 1.6758 |
| lookup_miss | new_us_per_lookup | 1.0973 |
| lookup_miss | speedup | 1.5272 |
| match | clone_us_per_match | 8.5060 |
| match | nomut_us_per_match | 5.4728 |
| match | pattern_count | 20 |
| match | speedup | 1.5542 |
| registration | legacy_time_ms | 1.9151 |
| registration | new_time_ms | 2.3036 |
| registration | pattern_count | 37 |
| registration | speedup | 0.8314 |

---

Full JSON: `baseline_pattern_engine.json`
