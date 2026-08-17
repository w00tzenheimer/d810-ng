# Domain-lifted semantic simplification: Task 15 rollout evidence

## Decision

This is an evidence-complete but not rollout-green result. The structural and
native adapter mechanisms are safety- and parity-proven in both Python and
Cython, but the manifest-wide native capture has no applied mutations and all
six Task 13 interactive rows are unavailable. The complete Cython system suite
and the portable unit gate are red for baseline or environment blockers. No
production defaults were changed: structural matching and fresh Egglog remain
opt-in, with legacy behavior as the default.

## Final tip, rebase, and workspace

- Final reviewed tip: `28a6d15cc835fe6034a3e5bdb4b0515c9eba86f2`
  (`fix(mba): fail closed shadow catalogue boundaries`).
- Rebase target at the reviewed rebase: local `cfg-recon-mainline`
  `ce87a09d807405a17e06d4f8f504945cc570c9f0`; divergence immediately after
  rebase was `0 behind / 36 ahead`.
- During the long final run the moving cfg ref advanced independently to
  `ba7cf2c3f2a151fb50fa553163783bf4f3c8a43a` (`ui: unify diagnostics capture
  controls`), an unrelated commit. The live final comparison is therefore
  `1 behind / 36 ahead`; the branch was not silently rebased during evidence
  generation, and no merge or push was performed.
- Rebase conflicts were semantically resolved in
  `tests/system/e2e/test_mba_native_corpus_capture.py` and
  `tests/system/e2e/test_mba_compiler_shape_corpus.py`, preserving the final
  capture, certificate, activation, and stale-evidence contracts.
- `git fetch --all --prune` encountered the known linked-worktree permission
  boundary; the known origin DNS failure was also recorded. Local and origin
  cfg tips were checked before proceeding; no remote tip was guessed.
- Tracked status was clean before adding this report. The pre-existing
  untracked binary was never staged or removed. The one graphify update attempt
  failed at the known linked-worktree permission boundary (`Operation not
  permitted`) and was not retried. Simba finalization belongs to the root
  agent's session ledger.

## Preserved generated-input binary

The pre-existing `samples/bins/mba_compiler_shapes.dylib` was moved
recoverably before the run and remains at:

```text
.tmp/preserved-untracked/mba_compiler_shapes.dylib
SHA-256: 693dca68a905ece9fdf80506aa2fe9263184fa4431be9e91d097d67781de203b
```

It was not restored under `samples/bins/`, staged, or deleted.

## Fresh artifact generation

All files below were regenerated after final tip `28a6d15cc`; the older
`.tmp/task15-final-artifacts/` directory was not used. The fresh root is
`.tmp/task15-final-tip-28a6d15cc/`, with separate `python/` and `cython/`
subdirectories.

### Manifest-wide captures

Python command:

```text
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
D810_MBA_NATIVE_CAPTURE_ARTIFACT_DIR=/work/.tmp/task15-final-tip-28a6d15cc/python \
./tools/scripts/run_system_tests_docker.sh test \
  -w domain-lifted-semantic-simplification \
  -o task15-final-manifest-python-final.log -- \
  tests/system/e2e/test_mba_native_corpus_capture.py::TestNativeMbaCorpusCapture::test_manifest_wide_native_capture_has_one_explicit_row_per_provider_case -q
```

Result: `1 passed, 122 warnings in 41.57s`, Docker exit 0.

Cython used the same command with `D810_NO_CYTHON=0`, the `cython` artifact
directory, and output `task15-final-manifest-cython-final.log`.

Result: `1 passed, 122 warnings in 37.63s`, Docker exit 0.

Separate 3 ms telemetry commands selected
`test_manifest_wide_native_capture_records_default_3ms_telemetry_separately`.
The Python result was `1 passed, 122 warnings in 36.82s` (Docker exit 0); the
Cython result was `1 passed, 122 warnings in 33.61s` (Docker exit 0).

The activation command was:

```text
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
D810_MBA_STRUCTURAL_PARITY_ARTIFACT_DIR=/work/.tmp/task15-final-tip-28a6d15cc/python \
./tools/scripts/run_system_tests_docker.sh test \
  -w domain-lifted-semantic-simplification \
  -o task15-final-activation-python.log -- \
  tests/system/e2e/test_mba_compiler_shape_corpus.py::TestCompilerShapeCatalogueNative::test_native_shadow_evidence_certificate_and_activation -q
```

Python result: `1 passed, 122 warnings in 114.55s` (Docker exit 0). Cython
used `D810_NO_CYTHON=0`, the `cython` artifact directory, and
`task15-final-activation-cython.log`; result was `1 passed, 122 warnings in
108.13s` (Docker exit 0).

After activation, the interactive JSON and Markdown reports were regenerated
from the post-activation captures with the offline reporter, using the
manifest, all five provider names, and the corresponding structural report
evidence sidecar:

```text
PYTHONPATH=src pyenv exec python tools/scripts/mba_differential_report.py \
  --out .tmp/task15-final-tip-28a6d15cc/<runtime>/mba-native-report-interactive-<runtime>.json \
  --markdown .tmp/task15-final-tip-28a6d15cc/<runtime>/mba-native-report-interactive-<runtime>.md \
  --manifest tests/fixtures/mba_portfolio/compiler_shapes.json \
  --providers structural_chain,catalogue,egglog,coefficient_solver,external_reference \
  --rollout-evidence .tmp/task15-final-tip-28a6d15cc/<runtime>/mba-structural-report-evidence-<runtime>.json \
  .tmp/task15-final-tip-28a6d15cc/<runtime>/mba-native-capture-interactive-<runtime>.json
```

### Capture and report observations

Both runtime matrices contain 76 cases and 380 provider rows:

| Runtime | Unavailable | Unchanged | Applied | Task 13 interactive rows unavailable |
| --- | ---: | ---: | ---: | ---: |
| Python | 378 | 2 | 0 | 6/6 |
| Cython | 378 | 2 | 0 | 6/6 |

Catalogue and structural-chain each have 75 unavailable plus one unchanged
row. Egglog, coefficient solver, and external reference are unavailable for all
76 rows. The separate telemetry reports have the same matrix and explicitly
record the Egglog `telemetry_3ms` lane for 76 cases; these are measurement
lanes, not useful native yield.

The compiler/toolchain identity in both reports is:

```text
compiler_executable: /usr/bin/aarch64-linux-gnu-gcc-14
compiler_version: aarch64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0
compiler_flags: -shared -fPIC -O0 -fno-inline -fno-builtin -fno-omit-frame-pointer -I /work/samples/include
ida_sdk: 940
profile: portfolio-interactive
```

The Python report has `matcher_backend=python`; the Cython report has
`matcher_backend=cython`; both were reported by `mba_differential_report`.

### Structural parity and activation

Python and Cython parity artifacts agree on:

```text
corpus_digest: b1bc1dbe6987a999f5a1c192d0197761f92479bf158ac28e8e8d11098bd3bd3e
snapshot_fingerprint: 1d97d7baeca8851bdb590830a486f98da8325c7f7efadda9ec80fc03e377b6ba
case_count: 76
provider_row_count: 380
observation_count: 185
legacy_match_count: 5
legacy_binding_mismatches: 0
legacy_binding_unknown: 0
legacy_rule_mismatches: 0
unsafe_mutations: 0
unproved_structural_replacements: 0
new_safe_coverage_pending: 0
new_safe_coverage_proved: 0
```

The snapshot is `structural_authorizable=true` in both parity JSON files. The
Python certificate toolchain digest is
`52476343b7d4eec8f9da210569b1b48c0235c90c32c9637efc136ce1988cdfb0`; the Cython
digest is
`8baf96ffe682085191e9f1885e79c71764a2305ef056d0aae7cd35bd751ded83`.
Activation artifacts bind the same corpus, observation count, and toolchain
digest. Stale-result artifacts were generated by mutating the corpus digest to
all zeroes; the persisted certificate expectation rejects that stale result.

### Final artifact SHA-256 ledger

The following hashes are the exact final-tip artifact files under
`.tmp/task15-final-tip-28a6d15cc/`.

#### Python

```text
mba-native-capture-activation-python.json 798a13377f99b1eef5116bdfa051fc5ea69b7f1e709130774b845847b9bb73da
mba-native-capture-interactive-python.json 7e1da759eac9ce54a9e9cd1bd00278b51c4592db3c15dd5c21d1bb5f137f771d
mba-native-capture-telemetry_3ms-python.json 29e883bc5c27f8b5a637f9c4ef9f4674f66658e94b6f640b3d573299808a9188
mba-native-report-interactive-python.json b69f7c3291e4a17181935942920e379aa2837ac1e83256088c8c31eedf3d85f2
mba-native-report-interactive-python.md 343986df37b88d766acb69374af14fcf707c45e3c3ddee981fc0b36ea5ead43f
mba-native-report-telemetry_3ms-python.json cb1b0f1c2d58d386b6a7685182295a24ce6059a252b8cc512fd5e0eb18fe6327
mba-native-report-telemetry_3ms-python.md a6dc7dc6ca777f368e61e92144f0b2d36a6e27b66c9ef5aa553c0981dd4df770
mba-native-telemetry-sidecar-interactive-python.json f058516a477dd1be0e82f81b97a7daa13c31778c13913432e2b03713b1dcfe00
mba-native-telemetry-sidecar-telemetry_3ms-python.json 4ba946b0be06198e5ef2f8d988e805e86d73619a5ecbb99df2ecf74e3a549b25
mba-structural-activation-python.json 88d8f5a4a8d765d44ab841be671fb6b277de639e8ee1390d657b571e8f012dd1
mba-structural-parity-python.certificate.json 5c635dde59e4671d7f21427f8062612422ae1076f7d3568b439ba4fa66bea155
mba-structural-parity-python.json e2afd5381d37b5d5279894354b22b8c2861028ed184df75d5c776a7f6bd37312
mba-structural-report-evidence-python.json bda0a7922b4a0b57cb872b5ee2870c0fbb7e91a253d55a396e2dda144b51d220
mba-structural-stale-python.json 62c6f05917bb63d126e245de4e8d529f3ad33344a413928795ab83f104d4e795
```

#### Cython

```text
mba-native-capture-activation-cython.json 0d72238e827d3aabda4c260583d94ce390f2a5f5ab80cce505e1300139af3a9c
mba-native-capture-interactive-cython.json c3aa823c683ad9e30e64832afe0d0fecb924f5c10ce7cb2aff8b925907c8ea52
mba-native-capture-telemetry_3ms-cython.json 0258a66c35919ca1832e80f43a620e13e8f7dd8ea92f694daa1bc5a45486cea2
mba-native-report-interactive-cython.json 7b98501eaa11de14f8aab3c9410a1f6ebe25396b0e4a3f55eb11e4a6f01b514c
mba-native-report-interactive-cython.md 58fa415d7ccd7ea6a9d1735fb3e64d0ff182932eca334b8c0ed5fb95d025ba2b
mba-native-report-telemetry_3ms-cython.json 22cc449dceb19bb96f46206b24673fa6bfa90b40cb864330f9ba61faabd5e750
mba-native-report-telemetry_3ms-cython.md 540cf8691d75ec2417015afea72c5aefa847466087e2da2a2e6a9d0256d01680
mba-native-telemetry-sidecar-interactive-cython.json 739e8b9e7c32cc9b3dca0d158f092538b3072c8e169a40e303d07fb042b72e74
mba-native-telemetry-sidecar-telemetry_3ms-cython.json 29b7d0d877d89f159bba6eb13ab33c348db953febf95d34d318866b3c4b6bc6a
mba-structural-activation-cython.json 9e3cb693fb3374e41afd846905a15edaef5b5c03f7ed1c860f812293d9e7cf28
mba-structural-parity-cython.certificate.json 5d5ddc34f99272478a96a7d1f6fba5ab67f910d344766b20fe337e1f07cf5896
mba-structural-parity-cython.json 4aaf788a71cf253a82d4179dc9a1abad39d3e4ed4ee71d0aebed69a21c833844
mba-structural-report-evidence-cython.json 66b262b103d119f4de8409a74bf52823b69675558eb5725130350c7fcd678e8d
mba-structural-stale-cython.json 70f27bfa759afa4130e578362edddce93f5aba217fcf53d7eb044ee6242082dc
```

## Focused and portable gates

The brief's exact focused command names
`tests/system/runtime/test_mba_provider_outcome_matrix.py`, which is not a
tracked path. The exact command therefore exited 4 before collection with
`file or directory not found` and 0 collected. The tracked path is
`tests/system/runtime/backends/test_mba_provider_outcome_matrix.py`.

Using that path, the otherwise identical 11-file focused Python command
completed with `239 passed, 6 skipped, 125 warnings in 294.38s` (Docker exit 0).
The Cython command with `D810_NO_CYTHON=0` completed with `242 passed, 3 skipped,
125 warnings in 257.55s` (Docker exit 0).

The exact portable commands were:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba
PYTHONPATH=src pyenv exec python tools/scripts/ruff_diff_gate.py --base cfg-recon-mainline
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
```

Portable pytest result: `698 passed, 3 skipped, 162 subtests passed, 2
failed in 175.72s`. The two failures are inherited fixed-count assertions in
`tests/unit/mba/test_egglog_mba_catalogue.py`: `cfg-recon-mainline` itself has
192 source declarations while the unchanged assertions expect 191. The other
four commands passed: ruff `All checks passed!`, sg 14 contracts kept / 0
broken, import-linter 14 contracts kept / 0 broken, and diff-check clean.

## Complete Cython system suite

The prescribed command was run from `/Users/mahmoud/src/idapro/d810` exactly:

```text
D810_NO_CYTHON=0 D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
./tools/scripts/run_system_tests_docker.sh system \
  -w domain-lifted-semantic-simplification -l \
  -o domain-lifted-final-system-cython.log -- -q
```

Terminal result: `4381 passed, 41 skipped, 11 deselected, 1 xfailed, 28
failed, 1 error in 1075.72s (0:17:55)`, Docker exit 1. The full-system log
SHA-256 is:

```text
domain-lifted-final-system-cython.log 7b99e85e51a13c6695dbe95f8a1a29a8dbe3299ee092433c8c1ddb175175fd81
```

The domain-lifted tests and the focused lanes are green. The red full-suite
clusters were isolated without edits:

| Group | Rollout branch | Clean cfg archive | Classification |
| --- | --- | --- | --- |
| Egglog spike pair | 2 failed | 1 failed, 1 passed | Baseline pseudocode literal-format mismatch; branch also logged degree 0 in one run |
| `test_manager_native_preanalysis.py` | 25 passed, 18 failed | 25 passed, 18 failed | Baseline lifecycle mock/contract mismatch |
| `test_optimizer_prefiltering.py` | 5 failed, 16 passed | 5 failed, 16 passed | Baseline mock/contract mismatch |
| table + XOR alone | 46 passed | 46 passed | Clean when isolated |
| speedup reload, then table + XOR | 3 failed, 44 passed | 3 failed, 44 passed | Reload-induced global identity/opcode state; reproduces baseline |
| SCCP performance test | 1 setup error | 1 setup error | Exact command omits required `D810_PERF_GATE=1` |

The first isolated branch spike command failed in 2.91s with an assertion
against the expected degree-one receipt; its detailed run also showed the
pre-existing decimal-vs-hex pseudocode formatting mismatch. No production or
test changes were made to mask any of these blockers.

## Evidence hashes for gate logs

```text
task15-final-manifest-python-final.log 63ee88688f04e84e3f1bfa744d6e7a95f718a68bc8298789fcbf2b489696809b
task15-final-manifest-cython-final.log 5c8ac6599c0506828385a10ce1a919c9122b4b5771e055c65fd63005df6e46d9
task15-final-telemetry-python.log 77d30a8ec3403ce110c4f65dafd898de060d6e2abe62637a6674a5833edc78ca
task15-final-telemetry-cython.log f6780f7bb188cf9090141435e5873dea78dcdf3540639243ef6e342ff3bdd627
task15-final-activation-python.log b1bd12398187ab16532fc97b9ee143d8dc172c1319e52597e773157a35e6424b
task15-final-activation-cython.log f4b8d141534d061e6687e186143010ebf9f84090df0b6d4bfa41b7a3192bc596
domain-lifted-final-focused-python-corrected.log 67a7d75c559a9376265ae5715d386cd9581b76337fd31003eee665c3eab3aa2f
domain-lifted-final-focused-cython-corrected.log 429ec5a779c7a063847c98ff119b45d5cfe5cac6eed4781c1f9229143449bb68
task15-isolate-spike-pair-cython.log e4e80991e845ddb029951f3c575bc4ff97a1dfd03cfb9b793c5fb116f5346bbd
task15-isolate-egglog-add-cython.log ced7310b4f68bbd887e7829b8b75752a8cdcb29ba59c20ac73fead89e72b6b15
task15-isolate-manager-preanalysis-cython.log 7c88d9d4dff2409ce92070de29be1d8563ff20f2d5c576f4d26b3beb63eeb64b
task15-isolate-optimizer-prefiltering-cython.log bbb5bc30b48c368978e04ea424ed9a6653e250afdd91ce4176f27f8f4059f8c7
task15-isolate-table-xor-cython.log bd185808a8179a6247b0dd5098f259cc0e0afdc7759c09991594e79fa89d0cfd
task15-isolate-sccp-perf-cython.log 11dc0c66b2fda5025c3273619aa9b473361965e1425721e27b2425468cf5b12a
task15-order-speedup-table-xor-cython.log c034ba62966f108fdc7ebe9337d33531e50d64d3b6613b71e7bd406c4b2fcd41
```

The final tracked report is the only file intended for the Task 15 rollout
commit; generated `.tmp` captures and logs remain ignored and unstaged.
