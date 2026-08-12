import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "tools" / "scripts" / "run_ida_gui_docker.sh"
CONNECTOR = REPO_ROOT / "tools" / "scripts" / "ida_gui_connect.py"
GUI_IMAGE = "test-gui-image"
GUI_RUNTIME_IMAGE = "idapro-9.4-speedups:x11"
GUI_RUNTIME_LABEL = "x11"
WORKTREE_NAME = "truthful-config-v2-project-ui"


def _write_checkout(path: Path) -> None:
    (path / "src" / "d810" / "ui").mkdir(parents=True, exist_ok=True)
    (path / "src" / "d810" / "__init__.py").write_text("", encoding="utf-8")
    (path / "src" / "d810" / "ui" / "__init__.py").write_text("", encoding="utf-8")
    (path / "src" / "d810" / "ui" / "gui_automation_logic.py").write_text(
        (REPO_ROOT / "src" / "d810" / "ui" / "gui_automation_logic.py").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    (path / "ida-plugin.json").write_text(
        '{"plugin": {"entryPoint": "src/d810ng.py"}}\n',
        encoding="utf-8",
    )
    (path / "src" / "d810ng.py").write_text(
        "def PLUGIN_ENTRY():\n    return None\n",
        encoding="utf-8",
    )
    if CONNECTOR.is_file():
        connector = path / "tools" / "scripts" / CONNECTOR.name
        connector.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CONNECTOR, connector)


def _parse_docker_calls(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    calls: list[list[str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "CALL":
            calls.append([])
        elif line.startswith("ARG="):
            calls[-1].append(line.removeprefix("ARG="))
        else:
            assert calls and calls[-1], line
            calls[-1][-1] += f"\n{line}"
    return calls


def _run(
    tmp_path: Path,
    *args: str,
    extra_env: dict[str, str] | None = None,
    use_gui_image_env: bool = True,
) -> tuple[subprocess.CompletedProcess[str], list[list[str]], dict[str, Path]]:
    if not LAUNCHER.is_file():
        pytest.fail(f"launcher missing: {LAUNCHER}")

    repo = tmp_path / "repo"
    _write_checkout(repo)
    worktree = repo / ".worktrees" / WORKTREE_NAME
    _write_checkout(worktree)
    alternate_worktree = repo / ".claude" / "worktrees" / "agent-ui"
    _write_checkout(alternate_worktree)
    outside = repo / "outside"
    _write_checkout(outside)

    samples = repo / "samples" / "bins"
    samples.mkdir(parents=True)
    (samples / "database with space.i64").write_text("sample", encoding="utf-8")

    ida_user = tmp_path / "ida-user"
    ida_user.mkdir()
    (ida_user / "idapro.hexlic").write_text("license", encoding="utf-8")
    mcp_source = tmp_path / "mcp source"
    (mcp_source / "src" / "ida_pro_mcp").mkdir(parents=True)
    (mcp_source / "ida-plugin.json").write_text(
        '{"plugin": {"entryPoint": "src/ida_pro_mcp/ida_mcp.py"}}\n',
        encoding="utf-8",
    )
    (mcp_source / "src" / "ida_pro_mcp" / "ida_mcp.py").write_text(
        "def PLUGIN_ENTRY():\n    return None\n",
        encoding="utf-8",
    )
    (ida_user / "plugins").mkdir()
    (ida_user / "plugins" / "ida-pro-mcp").symlink_to(
        mcp_source,
        target_is_directory=True,
    )
    d810_config = ida_user / "cfg" / "d810"
    d810_config.mkdir(parents=True)
    d810_logs = ida_user / "logs"
    d810_logs.mkdir()
    (d810_config / "options.json").write_text(
        json.dumps({"log_dir": str(d810_logs)}) + "\n",
        encoding="utf-8",
    )

    script = tmp_path / "run_ida_gui_docker.sh"
    shutil.copy2(LAUNCHER, script)
    script.chmod(0o755)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -eu
{
  printf 'CALL\\n'
  for arg in "$@"; do
    printf 'ARG=%s\\n' "$arg"
  done
} >> "$DOCKER_LOG"
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  [ "${MOCK_IMAGE_EXISTS:-1}" = 1 ] || exit 1
  case " $* " in
    *" --format "*) printf '%s\n' "${MOCK_GUI_RUNTIME_LABEL-x11}" ;;
  esac
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)

    xhost = bin_dir / "xhost"
    xhost.write_text(
        """#!/usr/bin/env bash
set -eu
[ "${MOCK_XHOST_FAIL:-0}" = 0 ] || exit 1
printf '%s\\n' 'access control enabled, only authorized clients can connect'
printf '%s\\n' "${MOCK_XHOST_ACCESS:-INET:localhost}"
""",
        encoding="utf-8",
    )
    xhost.chmod(0o755)

    env = os.environ.copy()
    for name in (
        "D810_REPO_ROOT",
        "D810_WORKTREE_ROOT",
        "D810_GUI_DOCKER_IMAGE",
        "D810_DOCKER_MEMORY",
        "D810_IDA_USER_DIR",
        "D810_GUI_DISPLAY",
        "D810_XHOST_BIN",
        "D810_MCP_PLUGIN_DIR",
        "MOCK_IMAGE_EXISTS",
        "MOCK_GUI_RUNTIME_LABEL",
        "MOCK_XHOST_FAIL",
        "MOCK_XHOST_ACCESS",
        "D810_DEBUG_LOGGING",
        "D810_DIAG_SNAPSHOT",
        "D810_FACT_LIFECYCLE",
    ):
        env.pop(name, None)
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "D810_REPO_ROOT": str(repo),
            "D810_IDA_USER_DIR": str(ida_user),
            "D810_XHOST_BIN": str(xhost),
        }
    )
    if use_gui_image_env:
        env["D810_GUI_DOCKER_IMAGE"] = GUI_IMAGE
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        [str(script), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    paths = {
        "repo": repo,
        "worktree": worktree,
        "alternate_worktree": alternate_worktree,
        "outside": outside,
        "samples": samples,
        "ida_user": ida_user,
        "d810_config": d810_config,
        "d810_logs": d810_logs,
        "mcp_source": mcp_source,
    }
    return result, _parse_docker_calls(docker_log), paths


def _assert_pair(args: list[str], flag: str, value: str) -> None:
    assert any(
        args[index] == flag and args[index + 1] == value
        for index in range(len(args) - 1)
    ), (flag, value, args)


def _automation_request(worktree: Path) -> tuple[Path, dict[str, object]]:
    request_paths = list(
        (worktree / ".tmp" / "ida-gui").glob("automation-request-*.json")
    )
    assert len(request_paths) == 1, request_paths
    request_path = request_paths[0]
    return request_path, json.loads(request_path.read_text(encoding="utf-8"))


def _automation_environment(run: list[str]) -> str:
    prefix = "D810_GUI_AUTOMATION_REQUEST="
    values = [
        run[index + 1]
        for index, value in enumerate(run[:-1])
        if value == "-e" and run[index + 1].startswith(prefix)
    ]
    assert len(values) == 1, values
    return values[0].removeprefix(prefix)


def _audit_path_for_request(request_path: Path) -> Path:
    request_id = request_path.name.removeprefix("automation-request-").removesuffix(
        ".json"
    )
    return request_path.parent / f"automation-{request_id}.json"


def test_default_launch_mounts_root_checkout_portable_d810_state_and_samples(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert calls[0][:3] == ["image", "inspect", "--format"]
    assert calls[0][-1] == GUI_IMAGE
    run = calls[1]
    assert run[:2] == ["run", "--rm"]
    _assert_pair(run, "--memory", "4g")
    _assert_pair(run, "-w", "/work")
    for value in (
        "MODE=x11",
        "DISPLAY=host.docker.internal:0",
        "LIBGL_ALWAYS_SOFTWARE=1",
        "PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python",
    ):
        _assert_pair(run, "-e", value)
    for value in (
        f"{paths['repo']}:/work",
        f"{paths['d810_config']}:/root/.idapro/cfg/d810",
        f"{paths['d810_logs']}:/root/.idapro/logs",
        f"{paths['d810_logs']}:{paths['d810_logs']}",
        f"{paths['repo']}:/root/.idapro/plugins/d810",
        f"{paths['samples']}:/samples/bins:ro",
    ):
        _assert_pair(run, "-v", value)
    assert f"{paths['ida_user']}:/root/.idapro" not in run
    _assert_pair(run, "--entrypoint", "/app/ida/entrypoint.sh")
    assert run[-1] == GUI_IMAGE
    assert f"checkout:  {paths['repo']}" in result.stdout
    assert f"d810 cfg:  {paths['d810_config']}" in result.stdout
    assert f"d810 logs: {paths['d810_logs']}" in result.stdout


def test_plain_launch_has_no_mcp_mount_environment_publication_or_intent(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(tmp_path, "--open-config")

    assert result.returncode == 0, result.stderr
    _request_path, document = _automation_request(paths["repo"])
    assert document["context"]["mcp_endpoint"] is None
    run = calls[-1]
    assert not any("ida-pro-mcp" in value for value in run)
    assert not any(value.startswith("IDA_MCP_") for value in run)
    assert "-p" not in run
    assert "mcp plugin:" not in result.stdout
    assert "mcp endpoint:" not in result.stdout


def test_mcp_mounts_resolved_source_read_only_and_publishes_only_loopback(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(tmp_path, "--mcp", "--open-config")

    assert result.returncode == 0, result.stderr
    request_path, document = _automation_request(paths["repo"])
    assert document["context"]["mcp_endpoint"] == "http://127.0.0.1:13337/mcp"
    run = calls[-1]
    _assert_pair(
        run,
        "-v",
        f"{paths['mcp_source'].resolve()}:/root/.idapro/plugins/ida-pro-mcp:ro",
    )
    _assert_pair(run, "-e", "IDA_MCP_HOST=0.0.0.0")
    _assert_pair(run, "-e", "IDA_MCP_PORT=13337")
    _assert_pair(run, "-e", "IDA_MCP_TOOL_TIMEOUT_SEC=45")
    _assert_pair(run, "-p", "127.0.0.1:13337:13337")
    _assert_pair(
        run,
        "-e",
        "PYTHONPATH=/root/.idapro/plugins/ida-pro-mcp/src/ida_pro_mcp:"
        "/root/.idapro/plugins/d810/src:/app/ida/python",
    )
    assert not any(
        value.endswith(":13337") and not value.startswith("127.0.0.1:")
        for index, value in enumerate(run)
        if index > 0 and run[index - 1] == "-p"
    )
    assert _automation_environment(run).endswith(request_path.name)
    escaped_mcp_source = str(paths["mcp_source"].resolve()).replace(" ", "\\ ")
    assert (
        f"mcp plugin: {escaped_mcp_source} -> "
        "/root/.idapro/plugins/ida-pro-mcp (read-only)"
    ) in result.stdout
    assert "mcp endpoint: http://127.0.0.1:13337/mcp" in result.stdout


def test_mcp_port_and_source_override_preserve_fixed_container_port(
    tmp_path: Path,
) -> None:
    override = tmp_path / "override mcp"
    (override / "src" / "ida_pro_mcp").mkdir(parents=True)
    (override / "ida-plugin.json").write_text("{}\n", encoding="utf-8")
    (override / "src" / "ida_pro_mcp" / "ida_mcp.py").write_text(
        "def PLUGIN_ENTRY():\n    return None\n",
        encoding="utf-8",
    )
    result, calls, paths = _run(
        tmp_path,
        "--mcp",
        "--mcp-port",
        "14444",
        "--open-workbench",
        extra_env={"D810_MCP_PLUGIN_DIR": str(override)},
    )

    assert result.returncode == 0, result.stderr
    _request_path, document = _automation_request(paths["repo"])
    assert document["context"]["mcp_endpoint"] == "http://127.0.0.1:14444/mcp"
    run = calls[-1]
    _assert_pair(
        run,
        "-v",
        f"{override.resolve()}:/root/.idapro/plugins/ida-pro-mcp:ro",
    )
    _assert_pair(run, "-e", "IDA_MCP_PORT=13337")
    _assert_pair(run, "-p", "127.0.0.1:14444:13337")
    assert not any(str(override) in value for value in run if value.startswith("D810_"))


@pytest.mark.parametrize("port", ("", "1023", "65536", "1e4", "+13337", "13337.0"))
def test_mcp_rejects_invalid_host_ports(tmp_path: Path, port: str) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "--mcp",
        "--mcp-port",
        port,
        "--open-config",
    )

    assert result.returncode != 0
    assert "--mcp-port" in result.stderr
    assert calls == []


def test_mcp_rejects_duplicate_port_flags(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "--mcp",
        "--mcp-port",
        "13337",
        "--mcp-port",
        "14444",
        "--open-config",
    )

    assert result.returncode != 0
    assert "--mcp-port may be specified only once" in result.stderr
    assert calls == []


def test_mcp_port_requires_mcp_opt_in(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "--mcp-port",
        "14444",
        "--open-config",
    )

    assert result.returncode != 0
    assert "--mcp-port requires --mcp" in result.stderr
    assert calls == []


def test_mcp_requires_a_closed_named_action(tmp_path: Path) -> None:
    result, calls, _paths = _run(tmp_path, "--mcp")

    assert result.returncode != 0
    assert "--mcp requires --open-config or --open-workbench" in result.stderr
    assert calls == []


def test_mcp_missing_plugin_source_fails_before_docker(tmp_path: Path) -> None:
    missing = tmp_path / "missing-mcp"
    result, calls, _paths = _run(
        tmp_path,
        "--mcp",
        "--open-config",
        extra_env={"D810_MCP_PLUGIN_DIR": str(missing)},
    )

    assert result.returncode != 0
    assert f"MCP plugin source not found: {missing}" in result.stderr
    assert calls == []


def test_connect_requires_a_closed_named_action_and_rejects_raw_ida_arguments(
    tmp_path: Path,
) -> None:
    missing_action, calls, _paths = _run(tmp_path / "missing", "--connect")
    raw_arguments, raw_calls, _paths = _run(
        tmp_path / "raw",
        "--connect",
        "--open-config",
        "--",
        "-A",
    )

    assert missing_action.returncode != 0
    assert (
        "--connect requires --open-config or --open-workbench" in missing_action.stderr
    )
    assert calls == []
    assert raw_arguments.returncode != 0
    assert "--connect does not accept IDA arguments after --" in raw_arguments.stderr
    assert raw_calls == []


@pytest.mark.parametrize("flag", ("--mcp", "--mcp-port"))
def test_connect_rejects_fresh_launch_mcp_flags(tmp_path: Path, flag: str) -> None:
    args = ["--connect", "--open-config", flag]
    if flag == "--mcp-port":
        args.append("14444")
    result, calls, _paths = _run(tmp_path, *args)

    assert result.returncode != 0
    assert "cannot be used with --connect" in result.stderr
    assert calls == []


def test_mcp_endpoint_is_connect_only_and_may_be_specified_once(tmp_path: Path) -> None:
    launch, calls, _paths = _run(
        tmp_path / "launch",
        "--mcp-endpoint",
        "http://127.0.0.1:14444/mcp",
        "--open-config",
    )
    duplicate, duplicate_calls, _paths = _run(
        tmp_path / "duplicate",
        "--connect",
        "--open-config",
        "--mcp-endpoint",
        "http://127.0.0.1:13337/mcp",
        "--mcp-endpoint",
        "http://localhost:14444/mcp",
    )

    assert launch.returncode != 0
    assert "--mcp-endpoint requires --connect" in launch.stderr
    assert calls == []
    assert duplicate.returncode != 0
    assert "--mcp-endpoint may be specified only once" in duplicate.stderr
    assert duplicate_calls == []


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://127.0.0.1:13337/mcp",
        "http://192.0.2.1:13337/mcp",
        "http://user@localhost:13337/mcp",
        "http://localhost:13337/mcp?ext=dbg",
        "http://localhost:13337/mcp#fragment",
        "http://localhost:13337/sse",
    ),
)
def test_connect_rejects_unsafe_mcp_endpoints_before_docker(
    tmp_path: Path,
    endpoint: str,
) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "--connect",
        "--open-config",
        "--mcp-endpoint",
        endpoint,
    )

    assert result.returncode != 0
    assert "loopback HTTP" in result.stderr
    assert calls == []


def test_connect_bypasses_xquartz_docker_ida_state_mcp_source_and_sample_copy(
    tmp_path: Path,
) -> None:
    missing_ida_user = tmp_path / "missing-ida-user"
    missing_mcp_source = tmp_path / "missing-mcp-source"
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--connect",
        "--open-workbench",
        "--function",
        "namespace::target",
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
        extra_env={
            "MOCK_XHOST_FAIL": "1",
            "MOCK_IMAGE_EXISTS": "0",
            "D810_IDA_USER_DIR": str(missing_ida_user),
            "D810_MCP_PLUGIN_DIR": str(missing_mcp_source),
        },
    )

    assert result.returncode != 0
    assert "MCP request failed" in result.stderr
    assert "xhost" not in result.stderr.lower()
    assert str(missing_ida_user) not in result.stderr
    assert str(missing_mcp_source) not in result.stderr
    assert calls == []
    assert not (paths["worktree"] / ".tmp" / "ida-gui").exists()
    assert list(paths["worktree"].rglob("*.i64")) == []


def test_plain_fresh_plan_names_every_non_applicable_automation_field(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(tmp_path)

    assert result.returncode == 0, result.stderr
    assert calls[-1][:2] == ["run", "--rm"]
    assert "D810 GUI pre-action plan:" in result.stdout
    assert "  mode: fresh plain" in result.stdout
    assert f"  selected worktree: {paths['repo']}" in result.stdout
    assert "  copied IDB: N/A" in result.stdout
    assert "  ordered commands: none" in result.stdout
    assert "  function selector: N/A" in result.stdout
    assert "  MCP endpoint: N/A" in result.stdout
    assert "  request path: N/A" in result.stdout
    assert "  audit path: N/A" in result.stdout


def test_named_fresh_plan_precedes_launch_and_reports_exact_artifacts(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--open-workbench",
        "--function",
        "0x401000",
        "--open-config",
        "--",
        "/samples/bins/database with space.i64",
    )

    assert result.returncode == 0, result.stderr
    request_path, _document = _automation_request(paths["worktree"])
    copied_idb = next((paths["worktree"] / ".tmp" / "ida-gui").glob("*.i64"))
    escaped_copied_idb = str(copied_idb).replace(" ", "\\ ")
    assert calls[-1][:2] == ["run", "--rm"]
    assert "D810 GUI pre-action plan:" in result.stdout
    assert "  mode: fresh named" in result.stdout
    assert f"  selected worktree: {paths['worktree']}" in result.stdout
    assert f"  copied IDB: {escaped_copied_idb}" in result.stdout
    assert "  ordered commands: open-config, open-workbench" in result.stdout
    assert "  function selector: 0x401000" in result.stdout
    assert "  MCP endpoint: N/A" in result.stdout
    assert f"  request path: {request_path}" in result.stdout
    assert f"  audit path: {_audit_path_for_request(request_path)}" in result.stdout


def test_named_fresh_mcp_plan_reports_loopback_endpoint_and_artifacts(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "--mcp",
        "--mcp-port",
        "14444",
        "--open-config",
    )

    assert result.returncode == 0, result.stderr
    request_path, _document = _automation_request(paths["repo"])
    assert calls[-1][:2] == ["run", "--rm"]
    assert "D810 GUI pre-action plan:" in result.stdout
    assert "  mode: fresh named MCP" in result.stdout
    assert f"  selected worktree: {paths['repo']}" in result.stdout
    assert "  copied IDB: N/A" in result.stdout
    assert "  ordered commands: open-config" in result.stdout
    assert "  function selector: N/A" in result.stdout
    assert "  MCP endpoint: http://127.0.0.1:14444/mcp" in result.stdout
    assert f"  request path: {request_path}" in result.stdout
    assert f"  audit path: {_audit_path_for_request(request_path)}" in result.stdout


def test_connect_plan_precedes_request_without_claiming_fresh_launch_actions(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--connect",
        "--open-config",
        "--open-workbench",
        "--function",
        "namespace::target",
        "--mcp-endpoint",
        "http://127.0.0.1:1/mcp",
    )

    assert result.returncode != 0
    assert "MCP request failed" in result.stderr
    assert calls == []
    assert "D810 GUI pre-action plan:" in result.stdout
    assert "  mode: connect" in result.stdout
    assert f"  selected worktree: {paths['worktree']}" in result.stdout
    assert "  copied IDB: N/A\\ \\(connect\\ mode\\)" in result.stdout
    assert "  ordered commands: open-config, open-workbench" in result.stdout
    assert "  function selector: namespace::target" in result.stdout
    assert "  MCP endpoint: http://127.0.0.1:1/mcp" in result.stdout
    assert "  request path: N/A\\ \\(sent\\ directly\\ over\\ MCP\\)" in result.stdout
    assert (
        f"  audit path: {paths['worktree']}/.tmp/ida-gui/"
        "automation-\\<request-id\\>.json"
    ) in result.stdout
    for fresh_only_claim in (
        "  image:",
        "  runtime:",
        "  display:",
        "MCP start",
        "Docker",
        "XQuartz",
    ):
        assert fresh_only_claim not in result.stdout


@pytest.mark.parametrize(
    ("mode_arguments", "field", "escaped_value", "forged_line"),
    (
        (
            (
                "--connect",
                "--open-workbench",
                "--function",
                "target\n  audit path: forged-selector",
                "--mcp-endpoint",
                "http://127.0.0.1:1/mcp",
            ),
            "function selector",
            "$'target\\n  audit path: forged-selector'",
            "  audit path: forged-selector",
        ),
        (
            (
                "--connect",
                "--open-config",
                "--mcp-endpoint",
                "http://127.0.0.1:1/mcp\n  audit path: forged-endpoint",
            ),
            "MCP endpoint",
            "$'http://127.0.0.1:1/mcp\\n  audit path: forged-endpoint'",
            "  audit path: forged-endpoint",
        ),
    ),
)
def test_connect_plan_shell_quotes_control_text_without_forged_fields(
    tmp_path: Path,
    mode_arguments: tuple[str, ...],
    field: str,
    escaped_value: str,
    forged_line: str,
) -> None:
    result, calls, _paths = _run(tmp_path, *mode_arguments)

    assert result.returncode != 0
    assert calls == []
    assert f"  {field}: {escaped_value}" in result.stdout
    plan_lines = result.stdout.splitlines()
    assert forged_line not in plan_lines
    assert len([line for line in plan_lines if line.startswith("  audit path:")]) == 1


@pytest.mark.parametrize(
    ("environment", "expected_line", "forged_line", "structured_prefix"),
    (
        (
            {"D810_DOCKER_MEMORY": "4g\n  display: forged-memory"},
            "  memory:    $'4g\\n  display: forged-memory'",
            "  display: forged-memory",
            "  display:",
        ),
        (
            {"D810_GUI_DISPLAY": ("host.docker.internal:0\n  image: forged-display")},
            "  display:   $'host.docker.internal:0\\n  image: forged-display'",
            "  image: forged-display",
            "  image:",
        ),
    ),
)
def test_fresh_detailed_plan_shell_quotes_environment_control_text(
    tmp_path: Path,
    environment: dict[str, str],
    expected_line: str,
    forged_line: str,
    structured_prefix: str,
) -> None:
    result, calls, _paths = _run(tmp_path, extra_env=environment)

    assert result.returncode == 0, result.stderr
    assert calls[-1][:2] == ["run", "--rm"]
    assert expected_line in result.stdout
    plan_lines = result.stdout.splitlines()
    assert forged_line not in plan_lines
    assert len([line for line in plan_lines if line.startswith(structured_prefix)]) == 1


def test_default_image_is_the_baked_d810_x11_runtime(tmp_path: Path) -> None:
    result, calls, _paths = _run(tmp_path, use_gui_image_env=False)

    assert result.returncode == 0, result.stderr
    assert GUI_RUNTIME_IMAGE in calls[0]
    assert calls[-1][-1] == GUI_RUNTIME_IMAGE


def test_image_without_gui_runtime_dependencies_is_rejected(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_GUI_RUNTIME_LABEL": ""},
    )

    assert result.returncode != 0
    assert "D810 GUI runtime" in result.stderr
    assert GUI_RUNTIME_LABEL in result.stderr
    assert not any(call[:2] == ["run", "--rm"] for call in calls)


def test_ida_94_x11_runtime_label_is_accepted(tmp_path: Path) -> None:
    """IDA 9.4's X11 images use the shorter runtime label."""
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_GUI_RUNTIME_LABEL": "x11"},
    )

    assert result.returncode == 0, result.stderr
    assert any(call[:2] == ["run", "--rm"] for call in calls)




def test_worktree_launch_copies_sample_database_and_preserves_other_ida_arguments(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--",
        "-A",
        "/samples/bins/database with space.i64",
    )

    assert result.returncode == 0, result.stderr
    run = calls[-1]
    _assert_pair(run, "-v", f"{paths['worktree']}:/work")
    _assert_pair(
        run,
        "-v",
        f"{paths['worktree']}:/root/.idapro/plugins/d810",
    )
    copies = list((paths["worktree"] / ".tmp" / "ida-gui").glob("*.i64"))
    assert len(copies) == 1
    assert copies[0].read_text(encoding="utf-8") == "sample"
    assert (paths["samples"] / "database with space.i64").read_text(
        encoding="utf-8"
    ) == "sample"
    image_index = run.index(GUI_IMAGE)
    assert run[image_index + 1 :] == [
        "-A",
        f"/work/.tmp/ida-gui/{copies[0].name}",
    ]


def test_open_config_writes_exact_request_and_injects_only_named_bootstrap(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--open-config",
    )

    assert result.returncode == 0, result.stderr
    request_path, document = _automation_request(paths["worktree"])
    request = document["request"]
    assert set(document) == {"request", "context"}
    assert set(request) == {
        "request_id",
        "created_at_utc",
        "commands",
        "function_selector",
        "timeout_seconds",
    }
    assert request_path.name == (f"automation-request-{request['request_id']}.json")
    assert request["created_at_utc"].endswith("Z")
    assert request["commands"] == ["open-config"]
    assert request["function_selector"] is None
    assert request["timeout_seconds"] == 30.0
    assert document["context"] == {
        "mode": "launch",
        "worktree": "/work",
        "idb": {"path": None, "sha256": None},
        "mcp_endpoint": None,
    }
    run = calls[-1]
    assert _automation_environment(run) == (f"/work/.tmp/ida-gui/{request_path.name}")
    image_index = run.index(GUI_IMAGE)
    assert run[image_index + 1 :] == ["-S/work/tools/scripts/ida_gui_bootstrap.py"]
    assert list(request_path.parent.glob("*.tmp")) == []


def test_open_workbench_validates_function_and_records_copied_idb_context(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        WORKTREE_NAME,
        "--open-workbench",
        "--function",
        "0x401000",
        "--",
        "-A",
        "/samples/bins/database with space.i64",
    )

    assert result.returncode == 0, result.stderr
    request_path, document = _automation_request(paths["worktree"])
    request = document["request"]
    assert request["commands"] == ["open-workbench"]
    assert request["function_selector"] == 0x401000
    copies = list((paths["worktree"] / ".tmp" / "ida-gui").glob("*.i64"))
    assert len(copies) == 1
    assert document["context"] == {
        "mode": "launch",
        "worktree": "/work",
        "idb": {
            "path": f"/work/.tmp/ida-gui/{copies[0].name}",
            "sha256": hashlib.sha256(b"sample").hexdigest(),
        },
        "mcp_endpoint": None,
    }
    run = calls[-1]
    assert _automation_environment(run).endswith(request_path.name)
    image_index = run.index(GUI_IMAGE)
    assert run[image_index + 1 :] == [
        "-S/work/tools/scripts/ida_gui_bootstrap.py",
        "-A",
        f"/work/.tmp/ida-gui/{copies[0].name}",
    ]


def test_both_named_flags_are_config_first_and_preserve_post_boundary_arguments(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "--open-workbench",
        "--function",
        "target",
        "--open-config",
        "--",
        "--open-config",
        "--function",
        "ida-owned-value",
    )

    assert result.returncode == 0, result.stderr
    _request_path, document = _automation_request(paths["repo"])
    assert document["request"]["commands"] == [
        "open-config",
        "open-workbench",
    ]
    assert document["request"]["function_selector"] == "target"
    run = calls[-1]
    image_index = run.index(GUI_IMAGE)
    assert run[image_index + 1 :] == [
        "-S/work/tools/scripts/ida_gui_bootstrap.py",
        "--open-config",
        "--function",
        "ida-owned-value",
    ]


def test_plain_launch_writes_no_request_and_preserves_caller_script_argument(
    tmp_path: Path,
) -> None:
    result, calls, paths = _run(
        tmp_path,
        "--",
        "-S/work/caller.py",
        "--open-workbench",
    )

    assert result.returncode == 0, result.stderr
    assert not (paths["repo"] / ".tmp" / "ida-gui").exists()
    run = calls[-1]
    assert not any(value.startswith("D810_GUI_AUTOMATION_REQUEST=") for value in run)
    image_index = run.index(GUI_IMAGE)
    assert run[image_index + 1 :] == [
        "-S/work/caller.py",
        "--open-workbench",
    ]


def test_function_without_workbench_is_rejected_as_an_empty_named_request(
    tmp_path: Path,
) -> None:
    result, calls, _paths = _run(tmp_path, "--function", "target")

    assert result.returncode != 0
    assert "--function requires --open-workbench" in result.stderr
    assert calls == []


@pytest.mark.parametrize("selector", ("", "target()", "0x401000 + 4"))
def test_workbench_rejects_invalid_function_selectors(
    tmp_path: Path,
    selector: str,
) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "--open-workbench",
        "--function",
        selector,
    )

    assert result.returncode != 0
    assert "function selector" in result.stderr
    assert not any(call[:2] == ["run", "--rm"] for call in calls)


def test_named_startup_rejects_a_conflicting_caller_script_argument(
    tmp_path: Path,
) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "--open-config",
        "--",
        "-S/work/caller.py",
    )

    assert result.returncode != 0
    assert "conflicting IDA -S" in result.stderr
    assert not any(call[:2] == ["run", "--rm"] for call in calls)


def test_system_runner_compatible_runtime_options_are_forwarded(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        "-l",
        "--enable-debug-logging",
        "--enable-diag-snapshot",
        "--disable-fact-lifecycle",
        extra_env={"D810_DOCKER_MEMORY": "6g", "D810_CUSTOM_GUI_TEST": "yes"},
    )

    assert result.returncode == 0, result.stderr
    run = calls[-1]
    _assert_pair(run, "--memory", "6g")
    for value in (
        "D810_DEBUG_LOGGING=1",
        "D810_DIAG_SNAPSHOT=1",
        "D810_FACT_LIFECYCLE=0",
        "D810_CUSTOM_GUI_TEST=yes",
    ):
        _assert_pair(run, "-e", value)
    assert "logs:     persistent D810 logs enabled (-l compatibility)" in result.stdout


def test_alternate_worktree_root_is_honored(tmp_path: Path) -> None:
    result, calls, paths = _run(
        tmp_path,
        "-w",
        "agent-ui",
        extra_env={"D810_WORKTREE_ROOT": ".claude/worktrees"},
    )

    assert result.returncode == 0, result.stderr
    _assert_pair(calls[-1], "-v", f"{paths['alternate_worktree']}:/work")


def test_missing_worktree_fails_before_docker(tmp_path: Path) -> None:
    result, calls, paths = _run(tmp_path, "-w", "missing")

    assert result.returncode != 0
    assert str(paths["repo"] / ".worktrees" / "missing") in result.stderr
    assert calls == []


def test_worktree_escape_is_rejected(tmp_path: Path) -> None:
    result, calls, _paths = _run(tmp_path, "-w", "../outside")

    assert result.returncode != 0
    assert "escapes worktree root" in result.stderr
    assert calls == []


def test_checkout_without_plugin_descriptor_is_rejected(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid-checkout"
    (invalid / "src").mkdir(parents=True)
    (invalid / "src" / "d810ng.py").write_text("", encoding="utf-8")
    result, calls, _paths = _run(
        tmp_path / "run",
        extra_env={"D810_REPO_ROOT": str(invalid)},
    )

    assert result.returncode != 0
    assert "ida-plugin.json" in result.stderr
    assert calls == []


def test_unavailable_xquartz_prints_recovery_commands(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_XHOST_FAIL": "1"},
    )

    assert result.returncode != 0
    assert "open -a XQuartz" in result.stderr
    assert "/opt/X11/bin/xhost +localhost" in result.stderr
    assert calls == []


def test_xquartz_without_localhost_authorization_is_rejected(
    tmp_path: Path,
) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_XHOST_ACCESS": "SI:localuser:test"},
    )

    assert result.returncode != 0
    assert "localhost is not authorized" in result.stderr
    assert calls == []


def test_missing_gui_image_fails_before_docker_run(tmp_path: Path) -> None:
    result, calls, _paths = _run(
        tmp_path,
        extra_env={"MOCK_IMAGE_EXISTS": "0"},
    )

    assert result.returncode != 0
    assert GUI_IMAGE in result.stderr
    assert len(calls) == 1
    assert calls[0][:3] == ["image", "inspect", "--format"]
    assert calls[0][-1] == GUI_IMAGE


def test_help_completely_documents_fresh_and_connect_contracts(tmp_path: Path) -> None:
    result, calls, _paths = _run(tmp_path, "--help")

    assert result.returncode == 0, result.stderr
    assert "-w, --worktree" in result.stdout
    assert "D810_WORKTREE_ROOT" in result.stdout
    assert "D810_IDA_USER_DIR" in result.stdout
    assert "--enable-debug-logging" in result.stdout
    assert "--enable-diag-snapshot" in result.stdout
    assert "--disable-fact-lifecycle" in result.stdout
    assert "--open-config" in result.stdout
    assert "--open-workbench" in result.stdout
    assert "--function" in result.stdout
    assert "--mcp" in result.stdout
    assert "--mcp-port" in result.stdout
    assert "--connect" in result.stdout
    assert "--mcp-endpoint" in result.stdout
    for restriction in (
        "--function requires --open-workbench",
        "--mcp requires --open-config or --open-workbench",
        "--mcp-port requires --mcp",
        "--connect requires --open-config or --open-workbench",
        "--connect does not accept IDA arguments after --",
        "--mcp-endpoint requires --connect",
    ):
        assert restriction in result.stdout
    assert "plain fresh docker launch" in result.stdout.lower()
    assert "fresh named automation" in result.stdout.lower()
    assert "existing session" in result.stdout.lower()
    assert "127.0.0.1" in result.stdout
    assert ".tmp/ida-gui/automation-request-<request-id>.json" in result.stdout
    assert ".tmp/ida-gui/automation-<request-id>.json" in result.stdout
    assert "samples/bins/libobfuscated.dll.2026-06-03.i64" in result.stdout
    assert "dylib" not in result.stdout.lower()
    assert "copy" in result.stdout.lower()
    assert "/samples/bins" in result.stdout
    assert (
        "Plain fresh arguments after -- remain separate array elements."
        in result.stdout
    )
    assert "/samples/bins/*.i64 is copied, verified, and rewritten" in result.stdout
    assert "to its /work/.tmp/ida-gui/ copy." in result.stdout
    assert "Named fresh rejects caller -S* arguments after --." in result.stdout
    assert "Connect rejects every argument after --." in result.stdout
    assert "Pass all remaining arguments to IDA unchanged." not in result.stdout
    assert (
        "--open-config        Open and focus the D-810 Configuration dock in the "
        "target IDA session."
    ) in result.stdout
    assert (
        "--open-workbench     Open and focus the D810 workbench in the target IDA "
        "session."
    ) in result.stdout
    assert "at startup" not in result.stdout
    assert calls == []
