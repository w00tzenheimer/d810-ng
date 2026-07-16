# Worktree-Aware IDA GUI Docker Launcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tested macOS launcher that runs the ARM64 IDA 9.3 GUI against a selected D810 worktree and a persistent host IDA user directory.

**Architecture:** A standalone Bash script resolves the canonical repository and optional `-w` checkout, validates XQuartz and the GUI image, then constructs one array-backed `docker run`. A pytest subprocess harness replaces Docker and `xhost` with deterministic fakes so path, mount, validation, and argument behavior are unit-testable without opening Qt.

**Tech Stack:** Bash 3.2-compatible arrays, Docker Desktop, XQuartz, pytest, Python `subprocess` and `pathlib`.

## Global Constraints

- Implement on `diff/truthful-config-v2-project-ui` in `/Users/mahmoud/src/idapro/d810/.worktrees/truthful-config-v2-project-ui`.
- Track the work under existing ticket `d81-kcin`.
- Default image is exactly `idapro-9.3:x11-arm64`; do not retag or modify `idapro-9.3:latest`.
- Default display is exactly `host.docker.internal:0`.
- Preserve localhost-only XQuartz authorization; never run unrestricted `xhost +`.
- Keep the root checkout and host `~/.idapro/plugins/d810` symlink unchanged.
- Hold Docker arguments in Bash arrays; do not use `eval` or reconstruct pass-through arguments as a command string.
- Mount the selected checkout and persistent host state read-write because project duplication, override saves, diagnostic databases, and IDB updates must persist.

---

### Task 1: Pin the launcher contract with subprocess tests

**Files:**
- Create: `tests/unit/tools/test_run_ida_gui_docker.py`
- Test: `tests/unit/tools/test_run_ida_gui_docker.py`

**Interfaces:**
- Consumes: planned executable `tools/scripts/run_ida_gui_docker.sh` and its environment variables from the design spec.
- Produces: `_run()` test harness returning the process result, Docker calls, and fake repository paths; ten tests covering the complete public contract.

- [ ] **Step 1: Write the failing test harness and contract tests**

Create a harness that fails explicitly when the launcher is absent, builds fake root/worktree checkouts containing `ida-plugin.json` and `src/d810ng.py`, creates a persistent `.idapro/idapro.hexlic`, and installs these exact fake commands:

```python
docker.write_text(
    """#!/usr/bin/env bash
set -eu
{
  printf 'CALL\\n'
  printf '%s\\n' "$@"
} >> "$DOCKER_LOG"
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  [ "${MOCK_IMAGE_EXISTS:-1}" = 1 ]
fi
""",
    encoding="utf-8",
)
xhost.write_text(
    """#!/usr/bin/env bash
set -eu
[ "${MOCK_XHOST_FAIL:-0}" = 0 ] || exit 1
printf '%s\\n' 'access control enabled, only authorized clients can connect'
printf '%s\\n' "${MOCK_XHOST_ACCESS:-INET:localhost}"
""",
    encoding="utf-8",
)
```

The ten test functions must assert these behaviors by inspecting Docker arguments as an ordered list:

- `test_default_launch_mounts_root_checkout_user_state_and_samples` asserts the root checkout, host IDA directory, canonical sample directory, X11 environment, selected Python path, entrypoint, and image.
- `test_worktree_launch_preserves_ida_arguments_and_mounts_selected_plugin` asserts both selected-worktree mounts and exact argument boundaries after the image.
- `test_alternate_worktree_root_is_honored` sets `D810_WORKTREE_ROOT=.claude/worktrees` and asserts that checkout is mounted.
- `test_missing_worktree_fails_before_docker` asserts a nonzero result, the resolved missing path, and no Docker calls.
- `test_worktree_escape_is_rejected` passes `../outside` and asserts the escape-specific error and no Docker calls.
- `test_checkout_without_plugin_descriptor_is_rejected` removes `ida-plugin.json` and asserts the descriptor-specific error and no Docker calls.
- `test_unavailable_xquartz_prints_recovery_commands` sets `MOCK_XHOST_FAIL=1` and asserts both approved recovery commands and no Docker calls.
- `test_xquartz_without_localhost_authorization_is_rejected` sets `MOCK_XHOST_ACCESS=SI:localuser:test` and asserts the localhost-specific error and no Docker calls.
- `test_missing_gui_image_fails_before_docker_run` sets `MOCK_IMAGE_EXISTS=0` and asserts exactly one `docker image inspect` call.
- `test_help_documents_worktrees_state_and_sample_mount` asserts `-w`, `D810_WORKTREE_ROOT`, `D810_IDA_USER_DIR`, `/samples/bins`, and no external calls.

For the pass-through assertion, invoke:

```python
result, calls, paths = _run(
    tmp_path,
    "-w",
    "truthful-config-v2-project-ui",
    "--",
    "/samples/bins/database with space.i64",
    "-A",
)
assert calls[-1][-2:] == ["/samples/bins/database with space.i64", "-A"]
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
PYTHONPATH=src pyenv exec python -m pytest tests/unit/tools/test_run_ida_gui_docker.py -q
```

Expected: all collected tests fail with a message ending in `tools/scripts/run_ida_gui_docker.sh`, proving the missing executable is the cause.

### Task 2: Implement the worktree-aware GUI launcher

**Files:**
- Create: `tools/scripts/run_ida_gui_docker.sh`
- Test: `tests/unit/tools/test_run_ida_gui_docker.py`

**Interfaces:**
- Consumes: `-w|--worktree NAME`, `-- [IDA_ARGS]`, and the five public environment overrides plus `D810_XHOST_BIN`.
- Produces: a foreground `docker run --rm` using `/app/ida/entrypoint.sh`, with the selected checkout at `/work` and `/root/.idapro/plugins/d810`, host state at `/root/.idapro`, and root samples at `/samples/bins`.

- [ ] **Step 1: Write the minimal array-backed launcher**

Implement these exact parsing and resolution boundaries:

```bash
WORKTREE_REL=""
IDA_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|--worktree)
      [ "$#" -ge 2 ] || fail "$1 requires a worktree name"
      WORKTREE_REL="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    --) shift; IDA_ARGS=("$@"); break ;;
    *) fail "unknown option: $1" ;;
  esac
done
```

Resolve directories with `cd "$path" && pwd -P`. For `-w`, reject absolute names and require the resolved checkout plus trailing slash to begin with the resolved worktree root plus trailing slash. Validate `ida-plugin.json`, `src/d810ng.py`, the IDA user directory, Docker availability, the image, `xhost`, and localhost authorization before launch.

Build the command as an array in this mount order:

```bash
DOCKER_ARGS=(
  run --rm
  -e "MODE=x11"
  -e "DISPLAY=$GUI_DISPLAY"
  -e "LIBGL_ALWAYS_SOFTWARE=1"
  -e "PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python"
  -v "$WORK_DIR:/work"
  -v "$IDA_USER_DIR:/root/.idapro"
  -v "$WORK_DIR:/root/.idapro/plugins/d810"
)
if [ -d "$SAMPLES_DIR" ]; then
  DOCKER_ARGS+=( -v "$SAMPLES_DIR:/samples/bins" )
fi
DOCKER_ARGS+=( --entrypoint /app/ida/entrypoint.sh "$DOCKER_IMAGE" )
DOCKER_ARGS+=( "${IDA_ARGS[@]}" )
exec docker "${DOCKER_ARGS[@]}"
```

Print a plan showing image, selected checkout, user-state mount, sample mount, display, and IDA arguments before `exec docker`.

- [ ] **Step 2: Make the launcher executable**

Run:

```bash
chmod +x tools/scripts/run_ida_gui_docker.sh
```

- [ ] **Step 3: Run the focused tests and verify GREEN**

Run:

```bash
PYTHONPATH=src pyenv exec python -m pytest tests/unit/tools/test_run_ida_gui_docker.py -q
```

Expected: `10 passed` with no Docker container or Qt process started.

- [ ] **Step 4: Run shell and repository checks**

Run:

```bash
bash -n tools/scripts/run_ida_gui_docker.sh
git diff --check
PYTHONPATH=src pyenv exec python -m pytest tests/unit/tools/test_run_system_tests_docker.py tests/unit/tools/test_run_ida_gui_docker.py -q
```

Expected: Bash syntax succeeds, diff check is clean, and both Docker-runner suites pass.

- [ ] **Step 5: Commit the tested launcher**

```bash
git add tools/scripts/run_ida_gui_docker.sh tests/unit/tools/test_run_ida_gui_docker.py
git commit -m "feat(gui): add worktree-aware IDA Docker launcher"
```

### Task 3: Prove the real XQuartz and sample-database path

**Files:**
- Modify: `.tickets/d81-kcin.md`

**Interfaces:**
- Consumes: the launcher from Task 2, active XQuartz localhost authorization, `idapro-9.3:x11-arm64`, worktree `truthful-config-v2-project-ui`, and `/samples/bins/libobfuscated.dylib.i64`.
- Produces: visible IDA/D810 acceptance evidence recorded on ticket `d81-kcin`.

- [ ] **Step 1: Verify the host preconditions**

Run:

```bash
/opt/X11/bin/xhost
docker image inspect idapro-9.3:x11-arm64 --format '{{.Id}} {{.Architecture}}'
```

Expected: `INET:localhost` or `INET6:localhost`, and an `arm64` image.

- [ ] **Step 2: Launch the selected worktree with a real database**

From the canonical repository root, run:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 \
  ./.worktrees/truthful-config-v2-project-ui/tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  -- /samples/bins/libobfuscated.dylib.i64
```

Expected: XQuartz displays IDA 9.3 with the named database open, and D810 reports version `0.6.6` from `/root/.idapro/plugins/d810/src`.

- [ ] **Step 3: Inspect the visible UI and terminate cleanly**

Use local computer control to confirm the IDA title/database and D810 workbench are present. Close IDA normally or send Ctrl-C to the foreground launcher, then confirm no launcher container remains.

- [ ] **Step 4: Record ticket evidence**

Append a dated note to `.tickets/d81-kcin.md` stating that the worktree-aware launcher, ten focused contract tests, the combined Docker-runner tests, and the real XQuartz launch of `libobfuscated.dylib.i64` passed, including the exact worktree and image tag above.

- [ ] **Step 5: Refresh graph and run final lifecycle checks**

```bash
graphify update .
simba codex-finalize
git diff --check
git status --short --branch
```

Expected: graph update succeeds, Simba finalization processes the session, diff check is clean, and only the intended ticket evidence remains before its final commit.

- [ ] **Step 6: Commit acceptance evidence**

```bash
git add .tickets/d81-kcin.md graphify-out
git commit -m "docs(gui): record Docker launcher acceptance"
```
