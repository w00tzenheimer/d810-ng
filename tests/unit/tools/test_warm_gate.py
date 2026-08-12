import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = REPO_ROOT / "tools" / "scripts"
WARM_GATE = SCRIPT_DIR / "warm_gate.sh"
RUNTIME_LABEL = "dev-emulation-z3-v1"


def _make_harness(tmp_path: Path) -> tuple[Path, Path]:
    script = tmp_path / "tools" / "scripts" / "warm_gate.sh"
    script.parent.mkdir(parents=True)
    shutil.copy2(WARM_GATE, script)
    # warm_gate.sh sources its sibling lib/dotenv.sh, so the copy needs the
    # whole lib/ beside it. Copying the script alone made `source` fail under
    # `set -e`: the script exited before touching docker, and every assertion
    # here died on a missing docker.log instead of on the behaviour it tests.
    shutil.copytree(SCRIPT_DIR / "lib", script.parent / "lib")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$DOCKER_LOG"
if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then
  printf '%s\\n' "${MOCK_DOCKER_LABEL:-}"
elif [ "${1:-}" = ps ] && [ "${MOCK_DOCKER_RUNNING:-0}" = 1 ]; then
  printf '%s\\n' "${D810_WARM_NAME:-d810-warm}"
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return script, docker_log


def _run_warm_gate(
    tmp_path: Path,
    command: str,
    *,
    label: str = "",
    running: bool = False,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    script, docker_log = _make_harness(tmp_path)
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{tmp_path / 'bin'}:{env['PATH']}",
            "DOCKER_LOG": str(docker_log),
            "MOCK_DOCKER_LABEL": label,
            "MOCK_DOCKER_RUNNING": "1" if running else "0",
            "D810_DOCKER_IMAGE": "test-runtime-image",
            "D810_WARM_NAME": "test-warm",
        }
    )
    result = subprocess.run(
        [str(script), command],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    calls = docker_log.read_text(encoding="utf-8").splitlines()
    return result, calls


def test_up_skips_automatic_setup_for_labeled_runtime_image(tmp_path: Path) -> None:
    result, calls = _run_warm_gate(tmp_path, "up", label=RUNTIME_LABEL)

    assert result.returncode == 0, result.stderr
    assert any(call.startswith("image inspect ") for call in calls)
    assert not any(call.startswith("exec ") for call in calls)
    assert "baked runtime dependencies detected; setup skipped" in result.stdout


def test_up_keeps_automatic_setup_for_unlabeled_image(tmp_path: Path) -> None:
    result, calls = _run_warm_gate(tmp_path, "up")

    assert result.returncode == 0, result.stderr
    assert any(call.startswith("exec ") for call in calls)
    assert "setup complete" in result.stdout


def test_explicit_setup_runs_for_labeled_runtime_image(tmp_path: Path) -> None:
    result, calls = _run_warm_gate(
        tmp_path,
        "setup",
        label=RUNTIME_LABEL,
        running=True,
    )

    assert result.returncode == 0, result.stderr
    assert any(call.startswith("exec ") for call in calls)
    assert "setup complete" in result.stdout
