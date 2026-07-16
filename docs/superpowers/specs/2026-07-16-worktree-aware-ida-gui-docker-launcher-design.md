# Worktree-Aware IDA GUI Docker Launcher Design

**Status:** Approved on 2026-07-16

**Ticket:** `d81-kcin`

## Goal

Provide a focused macOS launcher for the native ARM64 IDA 9.3 X11 image that selects a D810 checkout with the same `-w` convention as `tools/scripts/run_system_tests_docker.sh`, reuses portable D810 configuration and diagnostic state without replacing the image's Linux IDA registry, and opens disposable copies of canonical sample databases that are intentionally absent from linked worktrees.

## Scope

The launcher is `tools/scripts/run_ida_gui_docker.sh`. Its public interface is:

```bash
./tools/scripts/run_ida_gui_docker.sh [-w WORKTREE] [-- IDA_ARGS...]
```

Without `-w`, the selected checkout is `D810_REPO_ROOT`. With `-w NAME`, it is `D810_REPO_ROOT/D810_WORKTREE_ROOT/NAME`. `D810_WORKTREE_ROOT` defaults to `.worktrees`, matching the system-test runner. Arguments following `--` are passed to IDA unchanged and therefore use container paths.

The launcher supports these host environment overrides:

- `D810_REPO_ROOT`: canonical checkout containing `.worktrees` and local sample databases.
- `D810_WORKTREE_ROOT`: worktree directory relative to the canonical checkout; default `.worktrees`.
- `D810_GUI_DOCKER_IMAGE`: dependency-complete GUI image; default
  `idapro-9.3-speedups:x11-arm64`.
- `D810_DOCKER_MEMORY`: Docker memory limit; default `4g`, matching the system-test runner.
- `D810_IDA_USER_DIR`: persistent host IDA user directory; default `$HOME/.idapro`.
- `D810_GUI_DISPLAY`: container X11 display; default `host.docker.internal:0`.
- `D810_XHOST_BIN`: XQuartz access-control client; default `/opt/X11/bin/xhost`.

## Worktree and Data Mounts

The selected checkout is mounted read-write at `/work` and again at `/root/.idapro/plugins/d810`. The second mount is nested after the IDA user-directory mount, so it replaces the host-only `~/.idapro/plugins/d810` symlink inside the container. IDA therefore loads exactly the checkout selected by `-w`, independently of the native IDA process or host symlink.

The launcher does not mount the host IDA user directory over `/root/.idapro`. A whole-directory mount would replace the image's Linux `ida.reg` (whose `Python3TargetDLL` points at `/usr/local/lib/libpython3.13.so.1.0`) with the host macOS registry (whose Python target is a `.dylib`), preventing IDAPython from starting.

Instead, the host `cfg/d810` directory is mounted read-write at `/root/.idapro/cfg/d810`, and the configured D810 log directory is mounted read-write at `/root/.idapro/logs` and at the absolute path recorded in `options.json` when necessary. These scoped mounts reuse editable projects, `d810_function_rules.db`, diagnostic SQLite databases, and log artifacts while leaving the image-owned registry and license intact.

The canonical `D810_REPO_ROOT/samples/bins` directory is mounted read-only at `/samples/bins` when present. Local `.i64` files are ignored by Git and are not replicated into linked worktrees, so this separate mount gives every selected worktree the same databases without allowing IDA to modify the source artifacts.

When an IDA argument is `/samples/bins/*.i64`, the launcher copies it to the selected checkout's `.tmp/ida-gui/` directory, verifies the copy byte-for-byte, and replaces that argument with the corresponding `/work/.tmp/ida-gui/...` path. For example:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  -l -- /samples/bins/libobfuscated.dll.2026-06-03.i64
```

## Host and Container Validation

Before launch, the script:

1. Resolves and canonicalizes the repository root, worktree root, selected checkout, IDA user directory, and sample directory.
2. Rejects a missing worktree, a `-w` value that escapes the configured worktree root, or a checkout lacking `ida-plugin.json` and `src/d810ng.py`.
3. Requires Docker and verifies that `D810_GUI_DOCKER_IMAGE` exists.
4. Requires `/opt/X11/bin/xhost` and treats a successful `xhost` query as the XQuartz readiness signal. It does not rely on the application process name because the active server process is `Xquartz`/`X11.bin`, not `XQuartz`.
5. Requires access control to contain `INET:localhost` or `INET6:localhost`. On failure it prints the exact recovery commands `open -a XQuartz` and `/opt/X11/bin/xhost +localhost`; it never broadens access with unrestricted `xhost +`.

The container runs in the foreground with `--rm`, `--memory`, `-w /work`, `MODE=x11`, `DISPLAY`, `LIBGL_ALWAYS_SOFTWARE=1`, and `PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python`, using `/app/ida/entrypoint.sh` as its explicit entrypoint. The explicit Python path prevents a host editable install or unrelated checkout from shadowing the worktree selected by `-w`. Before launch, the image must expose `org.d810.gui-runtime=x11-dev-emulation-z3-v1`; this proves that the X11 image includes the same virtualenv dependencies and isolated Z3 speedups layer as the test runtime. The launcher also accepts the system runner's `-l`, `--enable-debug-logging`, `--enable-diag-snapshot`, and `--disable-fact-lifecycle` options and forwards non-wrapper `D810_*` environment variables. Ctrl-C terminates the GUI container. The existing CLI image and host plugin symlink are unchanged.

## Error Handling

Invalid options, missing option values, invalid paths, unavailable XQuartz, missing localhost authorization, and absent Docker images fail before `docker run`. Errors identify the rejected value and the required recovery action. Paths and pass-through arguments are held in Bash arrays so whitespace is preserved and no command is reconstructed through `eval`.

## Testing

`tests/unit/tools/test_run_ida_gui_docker.py` runs the real launcher against mocked `docker` and `xhost` executables. It covers:

- default root-checkout selection;
- `-w` selection under `.worktrees`;
- `D810_WORKTREE_ROOT` override;
- rejection of missing and escaping worktrees;
- selected-checkout and nested plugin mounts;
- scoped portable D810 state and read-only canonical sample mounts;
- automatic byte-for-byte sample database copying;
- system-runner-compatible memory, log, and diagnostic environment options;
- exact IDA argument preservation, including whitespace;
- Docker-image validation;
- XQuartz unavailable and localhost-not-authorized failures;
- help output that documents paths, state reuse, and sample paths.

After the mocked tests pass, live acceptance launches `idapro-9.3-speedups:x11-arm64` with `-w truthful-config-v2-project-ui` and a copied `libobfuscated.dll.2026-06-03.i64`. Acceptance requires the visible IDA GUI to open the `/work/.tmp/ida-gui/` copy, load D810 0.6.6 from the selected worktree with isolated Z3 available, expose the existing D810 configuration/log storage, and leave the canonical source hash unchanged. The live run is terminated after inspection.

## Non-Goals

- Changing or retagging the existing `idapro-9.3:latest` CLI image.
- Changing `tools/scripts/run_system_tests_docker.sh`.
- Extracting a shared shell library solely for this launcher.
- Supporting non-XQuartz display transports or non-macOS hosts in this slice.
- Changing the host `~/.idapro/plugins/d810` symlink.
