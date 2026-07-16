# Worktree-Aware IDA GUI Docker Launcher Design

**Status:** Approved on 2026-07-16

**Ticket:** `d81-kcin`

## Goal

Provide a focused macOS launcher for the native ARM64 IDA 9.3 X11 image that selects a D810 checkout with the same `-w` convention as `tools/scripts/run_system_tests_docker.sh`, reuses the user's IDA state, and can open the canonical sample databases that are intentionally absent from linked worktrees.

## Scope

The launcher is `tools/scripts/run_ida_gui_docker.sh`. Its public interface is:

```bash
./tools/scripts/run_ida_gui_docker.sh [-w WORKTREE] [-- IDA_ARGS...]
```

Without `-w`, the selected checkout is `D810_REPO_ROOT`. With `-w NAME`, it is `D810_REPO_ROOT/D810_WORKTREE_ROOT/NAME`. `D810_WORKTREE_ROOT` defaults to `.worktrees`, matching the system-test runner. Arguments following `--` are passed to IDA unchanged and therefore use container paths.

The launcher supports these host environment overrides:

- `D810_REPO_ROOT`: canonical checkout containing `.worktrees` and local sample databases.
- `D810_WORKTREE_ROOT`: worktree directory relative to the canonical checkout; default `.worktrees`.
- `D810_GUI_DOCKER_IMAGE`: GUI image; default `idapro-9.3:x11-arm64`.
- `D810_IDA_USER_DIR`: persistent host IDA user directory; default `$HOME/.idapro`.
- `D810_GUI_DISPLAY`: container X11 display; default `host.docker.internal:0`.
- `D810_XHOST_BIN`: XQuartz access-control client; default `/opt/X11/bin/xhost`.

## Worktree and Data Mounts

The selected checkout is mounted read-write at `/work` and again at `/root/.idapro/plugins/d810`. The second mount is nested after the IDA user-directory mount, so it replaces the host-only `~/.idapro/plugins/d810` symlink inside the container. IDA therefore loads exactly the checkout selected by `-w`, independently of the native IDA process or host symlink.

The host IDA user directory is mounted read-write at `/root/.idapro`. This reuses existing function-override state, diagnostics, and other IDA user data. The launch plan prints this writable state boundary before Docker starts.

The canonical `D810_REPO_ROOT/samples/bins` directory is mounted read-write at `/samples/bins` when present. Local `.i64` files are ignored by Git and are not replicated into linked worktrees, so this separate mount gives every selected worktree the same databases. For example:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  -- /samples/bins/libobfuscated.dylib.i64
```

## Host and Container Validation

Before launch, the script:

1. Resolves and canonicalizes the repository root, worktree root, selected checkout, IDA user directory, and sample directory.
2. Rejects a missing worktree, a `-w` value that escapes the configured worktree root, or a checkout lacking `ida-plugin.json` and `src/d810ng.py`.
3. Requires Docker and verifies that `D810_GUI_DOCKER_IMAGE` exists.
4. Requires `/opt/X11/bin/xhost` and treats a successful `xhost` query as the XQuartz readiness signal. It does not rely on the application process name because the active server process is `Xquartz`/`X11.bin`, not `XQuartz`.
5. Requires access control to contain `INET:localhost` or `INET6:localhost`. On failure it prints the exact recovery commands `open -a XQuartz` and `/opt/X11/bin/xhost +localhost`; it never broadens access with unrestricted `xhost +`.

The container runs in the foreground with `--rm`, `MODE=x11`, `DISPLAY`, `LIBGL_ALWAYS_SOFTWARE=1`, and `PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python`, using `/app/ida/entrypoint.sh` as its explicit entrypoint. The explicit Python path prevents a host editable install or unrelated checkout from shadowing the worktree selected by `-w`. Ctrl-C terminates the GUI container. The existing CLI image and host plugin symlink are unchanged.

## Error Handling

Invalid options, missing option values, invalid paths, unavailable XQuartz, missing localhost authorization, and absent Docker images fail before `docker run`. Errors identify the rejected value and the required recovery action. Paths and pass-through arguments are held in Bash arrays so whitespace is preserved and no command is reconstructed through `eval`.

## Testing

`tests/unit/tools/test_run_ida_gui_docker.py` runs the real launcher against mocked `docker` and `xhost` executables. It covers:

- default root-checkout selection;
- `-w` selection under `.worktrees`;
- `D810_WORKTREE_ROOT` override;
- rejection of missing and escaping worktrees;
- selected-checkout and nested plugin mounts;
- persistent IDA user-state and canonical sample mounts;
- exact IDA argument preservation, including whitespace;
- Docker-image validation;
- XQuartz unavailable and localhost-not-authorized failures;
- help output that documents paths, state reuse, and sample paths.

After the mocked tests pass, live acceptance launches `idapro-9.3:x11-arm64` with `-w truthful-config-v2-project-ui` and a real database from `/samples/bins`. Acceptance requires the visible IDA GUI to open that database and load D810 0.6.6 from the selected worktree. The live run is terminated cleanly after inspection.

## Non-Goals

- Rebuilding the GUI image; `idapro-9.3:x11-arm64` already exists and is verified.
- Changing `tools/scripts/run_system_tests_docker.sh`.
- Extracting a shared shell library solely for this launcher.
- Supporting non-XQuartz display transports or non-macOS hosts in this slice.
- Changing the host `~/.idapro/plugins/d810` symlink.
