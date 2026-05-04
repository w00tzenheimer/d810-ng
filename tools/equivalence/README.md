# Equivalence fuzz harness for `sub_7FFD3338C040`

Compares two ports of the function — the manually unflattened reference vs.
the D810 AFTER pseudocode — by running both on the same random inputs and
diffing their externally-visible behavior:

- return value
- final memory state of the caller-supplied buffer (`a5`, 16 KiB)
- ordered call trace (kind + 4 args per call) recorded by stub callees

## Files

| file        | purpose |
|-|-|
| `mock.h`    | shared typedefs (`__int64` etc as macros so `unsigned __int8` parses), `CallEvent` struct, `record()`, `MEM()` / stub callee declarations |
| `mock.c`    | trace buffers, deterministic stub returns, MEM() heuristic dispatch |
| `ref.c`     | reference function (manually unflattened) — `_gitless/sub_7FFD3338C040_unflattened.c` |
| `ours.c`    | D810 AFTER pseudocode — `.tmp/sub7FFD_default_on.txt` lines 99992-100297 |
| `harness.c` | main: random inputs, watchdog (SIGALRM) + crash recovery (SIGSEGV/SIGBUS/SIGFPE) via siglongjmp |
| `Makefile`  | `cc -O0 -g` with all the IDA-pseudocode warning suppressions |
| `run.sh`    | `make && ./harness K SEED`, defaults K=1000 SEED=42 |

## Usage

    ./run.sh                # K=1000 trials, seed=42
    ./run.sh 100 1337       # 100 trials, seed=1337
    EQ_VERBOSE=1 ./run.sh 20 42   # per-trial REF/OUR/done markers on stderr

Exit 0 = all trials passed (rv + memory + trace all match).
Exit 1 = at least one trial diverged.

## Stub model

`MEM(a, b, c, d)` (substitute for `MEMORY[0x180000000](...)`) dispatches to one
of three "kinds" by inspecting `a` and `b` against the constants the reference
uses (`0x4D / 0x5D` → kind `0x32FF8F30`, `0x55 / 0x62 / 0x44 / 0x2E` → kind
`0x33050180`, `0x11 / 0x2C / 0x27` → kind `0x333B4500`). Both sides record the
same kind so the trace is comparable.

Return values come from a deterministic content-derived hash so calls with
identical arguments return identical values on both sides.

`sub_7FFD32FF8F30` is bounded to `[2, 0x20]` even / occasionally `0x40` to
keep the loops bounded.

## Limitations

- `MEM` heuristic dispatch is a best-effort — both sides receive the same
  routing, but the routing itself is fictional. The trace tells us *whether
  ours and reference made the same call sequence with the same args*, not
  which native callee would have been invoked at runtime.

- The MBA byte-emit chain in the tail of both functions can produce arbitrary
  out-of-bounds shifts/indexes on random inputs. We catch SIGSEGV/SIGBUS/SIGFPE
  via siglongjmp and count them as `*_crashes`.

- `ours.c` contains uninitialized reads (e.g. `v8`, `v25`, `v33..v37`, `v50`,
  `v52`) that IDA's pseudocode preserves verbatim — kept as-is per the brief.
  These are zero-initialized in the prologue so the function is well-defined,
  but the values never match what would happen with the original loop fixpoint.

- `do { ... if (v44==1) break; ... } while ((v61 & 0x3E) != 2)` in `ours.c`
  has no progress in `v61` inside the loop body. With most randomized stub
  returns the loop never terminates — the watchdog (50 ms per side) catches
  this and counts as `our_hangs`. **This is a real divergence the harness
  surfaces**: D810's AFTER lost a critical loop-progress invariant.
