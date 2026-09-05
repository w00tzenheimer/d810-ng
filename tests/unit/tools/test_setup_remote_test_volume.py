"""Unit coverage for the one-time remote SMB volume helper."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools" / "scripts" / "setup_remote_test_volume.py"


def _load_module():
    specification = importlib.util.spec_from_file_location(
        "setup_remote_test_volume", MODULE_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


setup_remote_test_volume = _load_module()


def test_share_host_extracts_the_server() -> None:
    assert setup_remote_test_volume.share_host("//smb-server.example/idapro") == "smb-server.example"
    with pytest.raises(ValueError):
        setup_remote_test_volume.share_host("//")


def test_mount_options_default_to_owner_only_modes() -> None:
    options = setup_remote_test_volume.build_mount_options("hunter2")

    assert options == (
        "addr=smb-server.example,username=smbuser,password=hunter2,vers=3.0,"
        "uid=0,gid=0,file_mode=0700,dir_mode=0700"
    )
    assert "file_mode=0777" not in options
    assert "dir_mode=0777" not in options


def test_mount_options_omit_the_dropped_cifs_flags() -> None:
    """The user's option set drops nobrl/noperm; do not smuggle them back."""
    options = setup_remote_test_volume.build_mount_options("hunter2")

    assert "nobrl" not in options
    assert "noperm" not in options
    # credentials= is userspace-only (mount.cifs), so it must never appear.
    assert "credentials=" not in options


def test_mount_options_follow_the_share_and_user() -> None:
    options = setup_remote_test_volume.build_mount_options(
        "pw", share="//nas.example/work", user="tester"
    )

    assert options.startswith("addr=nas.example,username=tester,password=pw,")


def test_volume_argv_targets_the_remote_engine() -> None:
    command = setup_remote_test_volume.build_volume_argv(
        remote="remote-engine.example",
        volume="idapro",
        share="//smb-server.example/idapro",
        options="o-value",
    )

    assert command == [
        "docker",
        "-H",
        "ssh://remote-engine.example",
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=cifs",
        "--opt",
        "device=//smb-server.example/idapro",
        "--opt",
        "o=o-value",
        "idapro",
    ]


def test_redaction_hides_the_password_everywhere_it_appears() -> None:
    password = "hunter2"
    options = setup_remote_test_volume.build_mount_options(password)
    command = setup_remote_test_volume.build_volume_argv(
        remote="host", volume="idapro", share="//smb-server.example/idapro", options=options
    )

    redacted = setup_remote_test_volume.redact_argv(command, password)

    assert password not in " ".join(redacted)
    assert "password=********" in " ".join(redacted)
    assert len(redacted) == len(command)


def test_redaction_leaves_argv_alone_for_an_empty_password() -> None:
    command = ["docker", "volume", "create", "idapro"]

    assert setup_remote_test_volume.redact_argv(command, "") == command


def test_dry_run_prints_the_redacted_argv_and_runs_no_docker(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("--dry-run must not run docker")

    monkeypatch.setattr(setup_remote_test_volume.subprocess, "run", _fail)

    status = setup_remote_test_volume.main(["--dry-run"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "hunter2" not in printed
    assert "password=********" in printed
    assert "ssh://remote-engine.example" in printed
    assert "file_mode=0700,dir_mode=0700" in printed


def test_failure_reports_one_line_and_a_nonzero_status(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )

    def _fail(command: list[str], **kwargs: object) -> None:
        raise setup_remote_test_volume.subprocess.CalledProcessError(7, command)

    monkeypatch.setattr(setup_remote_test_volume.subprocess, "run", _fail)

    status = setup_remote_test_volume.main([])
    captured = capsys.readouterr()

    assert status == 7
    assert captured.err.strip().splitlines() == [
        "ERROR: docker volume create failed with exit status 7"
    ]
    assert "hunter2" not in captured.out


def test_success_runs_the_built_argv(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[list[str]] = []
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess,
        "run",
        lambda command, **kwargs: recorded.append(list(command)),
    )

    status = setup_remote_test_volume.main(["--volume", "other", "--user", "tester"])
    printed = capsys.readouterr().out

    assert status == 0
    assert recorded and recorded[0][-1] == "other"
    assert "username=tester" in " ".join(recorded[0])
    assert "hunter2" not in printed
    assert "docker volume inspect other" in printed


def test_doctests_pass() -> None:
    import doctest

    results = doctest.testmod(setup_remote_test_volume, verbose=False)
    assert results.failed == 0, results
