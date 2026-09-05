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


@pytest.fixture(autouse=True)
def _generic_remote_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("D810_REMOTE_DOCKER_HOST", "runner.example")
    monkeypatch.setenv("D810_REMOTE_SMB_SHARE", "//files.example/project")
    monkeypatch.setenv("D810_REMOTE_SMB_USER", "share-account")
    monkeypatch.setenv("D810_REMOTE_SHARE_ROOT", "/srv/project")


def test_configuration_loads_from_nearest_ignored_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in setup_remote_test_volume.REMOTE_CONFIG_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("D810_ENV_FILE", raising=False)
    nested = tmp_path / ".worktrees" / "runner"
    nested.mkdir(parents=True)
    (tmp_path / ".env").write_text(
        "D810_REMOTE_DOCKER_HOST=runner.example\n"
        "D810_REMOTE_SMB_SHARE=//files.example/project\n"
        "D810_REMOTE_SMB_USER=share-account\n"
        f"D810_REMOTE_SHARE_ROOT={tmp_path}\n"
        "IGNORED_SECRET=do-not-import\n",
        encoding="utf-8",
    )

    configuration = setup_remote_test_volume.load_remote_configuration(nested)

    assert configuration == {
        "D810_REMOTE_DOCKER_HOST": "runner.example",
        "D810_REMOTE_SMB_SHARE": "//files.example/project",
        "D810_REMOTE_SMB_USER": "share-account",
        "D810_REMOTE_SHARE_ROOT": str(tmp_path),
    }


def test_missing_machine_configuration_fails_before_password_or_docker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in setup_remote_test_volume.REMOTE_CONFIG_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("D810_ENV_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        setup_remote_test_volume.getpass,
        "getpass",
        lambda prompt: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not run docker")),
    )

    status = setup_remote_test_volume.main(["--dry-run"])

    assert status == 2
    assert "missing remote configuration" in capsys.readouterr().err


def test_share_host_extracts_the_server() -> None:
    assert setup_remote_test_volume.share_host("//files.example/project") == "files.example"
    with pytest.raises(ValueError):
        setup_remote_test_volume.share_host("//")


def test_mount_options_default_to_owner_only_modes() -> None:
    options = setup_remote_test_volume.build_mount_options(
        "test-password", share="//files.example/project", user="share-account"
    )

    assert options == (
        "addr=files.example,username=share-account,password=test-password,vers=3.0,"
        "uid=0,gid=0,file_mode=0700,dir_mode=0700"
    )
    assert "file_mode=0777" not in options
    assert "dir_mode=0777" not in options


def test_mount_options_omit_the_dropped_cifs_flags() -> None:
    """The user's option set drops nobrl/noperm; do not smuggle them back."""
    options = setup_remote_test_volume.build_mount_options(
        "test-password", share="//files.example/project", user="share-account"
    )

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
        remote="runner.example",
        volume="idapro",
        share="//files.example/project",
        options="o-value",
    )

    assert command == [
        "docker",
        "-H",
        "ssh://runner.example",
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=cifs",
        "--opt",
        "device=//files.example/project",
        "--opt",
        "o=o-value",
        "idapro",
    ]


def test_redaction_hides_the_password_everywhere_it_appears() -> None:
    password = "test-password"
    options = setup_remote_test_volume.build_mount_options(
        password, share="//files.example/project", user="share-account"
    )
    command = setup_remote_test_volume.build_volume_argv(
        remote="host", volume="idapro", share="//files.example/project", options=options
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
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "test-password"
    )

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("--dry-run must not run docker")

    monkeypatch.setattr(setup_remote_test_volume.subprocess, "run", _fail)
    for seam in ("run_capture", "run_probe"):
        monkeypatch.setattr(
            setup_remote_test_volume,
            seam,
            lambda argv: (_ for _ in ()).throw(
                AssertionError("--dry-run must not run docker")
            ),
        )

    status = setup_remote_test_volume.main(["--dry-run"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "test-password" not in printed
    assert "password=********" in printed
    assert "ssh://runner.example" in printed
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

    monkeypatch.setattr(
        setup_remote_test_volume, "run_capture", lambda argv: (1, ABSENT_ERROR)
    )
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
        setup_remote_test_volume, "run_capture", lambda argv: (1, ABSENT_ERROR)
    )
    monkeypatch.setattr(
        setup_remote_test_volume, "run_probe", lambda argv: (0, "mount-ok\n")
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


ABSENT_ERROR = "Error response from daemon: get idapro: no such volume"
SSH_ERROR = "error during connect: ssh: connect to host runner.example port 22: refused"

INSPECT_PAYLOAD = (
    '[{"Name": "idapro", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/idapro/_data",'
    ' "Options": {"device": "//files.example/project", "o":'
    ' "addr=files.example,username=share-account,password=test-password,vers=3.0,uid=0,gid=0,'
    'file_mode=0700,dir_mode=0700", "type": "cifs"}}]'
)


def _fake_capture(monkeypatch: pytest.MonkeyPatch, responses: dict[str, tuple[int, str]]):
    """Route run_capture by the docker sub-command, recording every argv."""
    recorded: list[list[str]] = []

    def _capture(argv):
        argv = list(argv)
        recorded.append(argv)
        for key, response in responses.items():
            if key in " ".join(argv):
                if isinstance(response, list):
                    # A sequence models a value that changes between calls,
                    # e.g. dmesg captured before and after the probe.
                    return response.pop(0) if len(response) > 1 else response[0]
                return response
        return (0, "")

    monkeypatch.setattr(setup_remote_test_volume, "run_capture", _capture)
    monkeypatch.setattr(setup_remote_test_volume, "run_probe", _capture)
    return recorded


def test_inspect_and_filter_argv_shapes() -> None:
    assert setup_remote_test_volume.build_inspect_argv(remote="h", volume="v") == [
        "docker", "-H", "ssh://h", "volume", "inspect", "v",
    ]
    assert setup_remote_test_volume.build_container_filter_argv(remote="h", volume="v") == [
        "docker", "-H", "ssh://h", "ps", "-a", "--filter", "volume=v",
        "--format", "{{.ID}} {{.Status}} {{.Names}}",
    ]
    assert setup_remote_test_volume.build_remove_volume_argv(remote="h", volume="v") == [
        "docker", "-H", "ssh://h", "volume", "rm", "v",
    ]
    assert setup_remote_test_volume.build_remove_containers_argv(
        remote="h", container_ids=["a", "b"]
    ) == ["docker", "-H", "ssh://h", "rm", "-f", "a", "b"]
    with pytest.raises(ValueError):
        setup_remote_test_volume.build_remove_containers_argv(remote="h", container_ids=[])


def test_status_output_redacts_the_stored_password() -> None:
    rendered = setup_remote_test_volume.format_status(INSPECT_PAYLOAD, "")

    assert "test-password" not in rendered
    assert "password=********" in rendered
    assert "driver:  local" in rendered
    assert "device:  //files.example/project" in rendered
    assert "type:    cifs" in rendered
    assert "containers referencing the volume: none" in rendered


def test_status_output_lists_referencing_containers() -> None:
    rendered = setup_remote_test_volume.format_status(
        INSPECT_PAYLOAD, "abc123 Exited (137) 2 minutes ago sad_hopper\n"
    )

    assert "containers referencing the volume:" in rendered
    assert "  abc123 Exited (137) 2 minutes ago sad_hopper" in rendered


def test_status_output_survives_unparseable_inspect() -> None:
    rendered = setup_remote_test_volume.format_status("not json", "")

    assert "driver:  unknown" in rendered


@pytest.mark.parametrize(
    "containers,force,expected",
    [
        ([], False, "proceed"),
        ([], True, "proceed"),
        (["a Exited n"], False, "refuse"),
        (["a Exited n"], True, "force"),
    ],
)
def test_removal_decision(containers: list[str], force: bool, expected: str) -> None:
    assert setup_remote_test_volume.removal_decision(containers, force) == expected


def test_status_mode_reports_present_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(
        monkeypatch,
        {"volume inspect": (0, INSPECT_PAYLOAD), "ps -a": (0, "abc Up 3 minutes runner\n")},
    )

    status = setup_remote_test_volume.main(["--status"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "hunter2" not in printed
    assert "password=********" in printed
    assert "abc Up 3 minutes runner" in printed


def test_status_mode_reports_absent_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(monkeypatch, {"volume inspect": (1, ABSENT_ERROR)})

    status = setup_remote_test_volume.main(["--status"])

    assert status == 1
    assert "is absent" in capsys.readouterr().out


def test_remove_refuses_while_containers_reference_the_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {"volume inspect": (0, INSPECT_PAYLOAD), "ps -a": (0, "abc Exited (137) leftover\n")},
    )

    status = setup_remote_test_volume.main(["--remove"])
    captured = capsys.readouterr()

    assert status == 1
    assert "abc Exited (137) leftover" in captured.err
    assert "--rm" in captured.err
    assert not any("volume rm" in " ".join(argv) for argv in recorded)


def test_remove_with_force_kills_containers_then_the_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {"volume inspect": (0, INSPECT_PAYLOAD), "ps -a": (0, "abc Exited (137) leftover\n")},
    )

    status = setup_remote_test_volume.main(["--remove", "--force"])
    printed = capsys.readouterr().out

    assert status == 0
    joined = [" ".join(argv) for argv in recorded]
    assert any("rm -f abc" in call for call in joined)
    assert joined.index([c for c in joined if "rm -f abc" in c][0]) < joined.index(
        [c for c in joined if "volume rm" in c][0]
    )
    assert "stored SMB credential is deleted" in printed
    assert "remote-run.lock" in printed


def test_remove_is_idempotent_when_absent(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(monkeypatch, {"volume inspect": (1, ABSENT_ERROR)})

    status = setup_remote_test_volume.main(["--remove"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "already absent" in printed
    assert not any("volume rm" in " ".join(argv) for argv in recorded)


def test_remove_never_touches_worktree_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tmp_path / ".tmp" / "remote-run.lock"
    lock.mkdir(parents=True)
    _fake_capture(monkeypatch, {"volume inspect": (0, INSPECT_PAYLOAD)})

    assert setup_remote_test_volume.main(["--remove"]) == 0
    assert lock.is_dir()


def test_create_refuses_an_existing_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(monkeypatch, {"volume inspect": (0, INSPECT_PAYLOAD)})

    def _fail(prompt: str) -> str:
        raise AssertionError("must refuse before prompting for a password")

    monkeypatch.setattr(setup_remote_test_volume.getpass, "getpass", _fail)

    status = setup_remote_test_volume.main([])

    assert status == 1
    assert "already exists" in capsys.readouterr().err


def test_recreate_removes_then_creates(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(monkeypatch, {"volume inspect": (0, INSPECT_PAYLOAD)})
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    created: list[list[str]] = []
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess,
        "run",
        lambda command, **kwargs: created.append(list(command)),
    )

    status = setup_remote_test_volume.main(["--recreate"])
    printed = capsys.readouterr().out

    assert status == 0
    assert any("volume rm" in " ".join(argv) for argv in recorded)
    assert created and "volume" in created[0] and "create" in created[0]
    assert "hunter2" not in printed


def test_dry_run_covers_status_and_remove_modes(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fail(argv):
        raise AssertionError("--dry-run must not run docker")

    monkeypatch.setattr(setup_remote_test_volume, "run_capture", _fail)

    assert setup_remote_test_volume.main(["--status", "--dry-run"]) == 0
    status_output = capsys.readouterr().out
    assert "volume inspect idapro" in status_output
    assert "--filter volume=idapro" in status_output

    assert setup_remote_test_volume.main(["--remove", "--dry-run", "--force"]) == 0
    remove_output = capsys.readouterr().out
    assert "--filter volume=idapro" in remove_output
    assert "rm -f <containers listed above>" in remove_output
    assert "volume rm idapro" in remove_output


def test_status_and_remove_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        setup_remote_test_volume.main(["--status", "--remove"])


def test_probe_argv_shapes() -> None:
    assert setup_remote_test_volume.build_verify_probe_argv(
        remote="h", volume="v"
    ) == [
        "docker", "-H", "ssh://h", "run", "--rm", "--mount",
        "type=volume,src=v,dst=/probe,readonly", "alpine", "sh", "-c",
        "ls /probe >/dev/null && echo mount-ok",
    ]
    assert setup_remote_test_volume.build_kernel_dmesg_argv(
        remote="h", image="other"
    ) == [
        "docker", "-H", "ssh://h", "run", "--rm", "--privileged", "other", "sh", "-c",
        "dmesg",
    ]
    default_kernel = setup_remote_test_volume.build_kernel_dmesg_argv(remote="h")
    assert default_kernel[6].startswith("alpine@sha256:")


def test_kernel_delta_attributes_only_new_status_lines() -> None:
    before = "[1.0] CIFS: Status code returned 0xc000006e OLD"
    after = before + "\n[2.0] CIFS: Status code returned 0xc000006d NEW\n[3.0] unrelated"

    assert setup_remote_test_volume.dmesg_status_delta(before, after) == [
        "[2.0] CIFS: Status code returned 0xc000006d NEW"
    ]
    assert setup_remote_test_volume.dmesg_status_delta(before, before) == []


def test_failed_probe_without_the_flag_stays_unprivileged(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kernel diagnosis must be opt-in: no privileged container by default."""
    recorded = _fake_capture(
        monkeypatch,
        {"volume inspect": (0, INSPECT_PAYLOAD), "dst=/probe": (1, "permission denied")},
    )

    status = setup_remote_test_volume.main(["--status"])
    captured = capsys.readouterr()

    assert status == 1
    assert "permission denied" in captured.err
    assert "--kernel-diagnosis" in captured.err
    assert not any("--privileged" in " ".join(argv) for argv in recorded)


def test_kernel_diagnosis_captures_dmesg_before_and_after(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dmesg_captures = iter(
        [
            (0, "[1.0] CIFS: Status code returned 0xc000006e OLD"),
            (
                0,
                "[1.0] CIFS: Status code returned 0xc000006e OLD\n"
                "[2.0] CIFS: Status code returned 0xc000006d LOGON",
            ),
        ]
    )
    recorded: list[list[str]] = []

    def _capture(argv):
        argv = list(argv)
        recorded.append(argv)
        joined = " ".join(argv)
        if "--privileged" in joined:
            return next(dmesg_captures)
        if "dst=/probe" in joined:
            return (1, "permission denied")
        if "volume inspect" in joined:
            return (0, INSPECT_PAYLOAD)
        return (0, "")

    monkeypatch.setattr(setup_remote_test_volume, "run_capture", _capture)
    monkeypatch.setattr(setup_remote_test_volume, "run_probe", _capture)

    status = setup_remote_test_volume.main(["--status", "--kernel-diagnosis"])
    captured = capsys.readouterr()

    assert status == 1
    joined = [" ".join(argv) for argv in recorded]
    privileged = [index for index, call in enumerate(joined) if "--privileged" in call]
    probe_index = next(index for index, call in enumerate(joined) if "dst=/probe" in call)
    assert len(privileged) == 2
    assert privileged[0] < probe_index < privileged[1]
    assert "0xc000006d" in captured.err
    assert "0xc000006e" not in captured.err  # pre-existing line is not attributed


def test_kernel_diagnosis_reports_an_empty_delta(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(
        monkeypatch,
        {
            "volume inspect": (0, INSPECT_PAYLOAD),
            "dst=/probe": (1, "permission denied"),
            "--privileged": (0, "[1.0] CIFS: Status code returned 0xc000006e OLD"),
        },
    )

    status = setup_remote_test_volume.main(["--status", "--kernel-diagnosis"])

    assert status == 1
    assert "no new CIFS status line" in capsys.readouterr().err


@pytest.mark.parametrize(
    "line,fragment",
    [
        ("CIFS: Status code returned 0xc000006d NT_STATUS_LOGON_FAILURE", "LOGON_FAILURE"),
        ("CIFS: Status code returned 0xc000006e STATUS_ACCOUNT_RESTRICTION", "ACCOUNT_RESTRICTION"),
        ("CIFS: Status code returned 0xc00000cc BAD_NETWORK_NAME", "BAD_NETWORK_NAME"),
        ("unrelated", "no known CIFS status code"),
    ],
)
def test_status_code_explanations(line: str, fragment: str) -> None:
    assert fragment in setup_remote_test_volume.explain_status_code(line)


def test_comma_password_is_refused_before_any_volume_create(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(monkeypatch, {"volume inspect": (1, ABSENT_ERROR)})
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "bad,password"
    )

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("a comma password must never reach docker volume create")

    monkeypatch.setattr(setup_remote_test_volume.subprocess, "run", _fail)

    status = setup_remote_test_volume.main([])
    captured = capsys.readouterr()

    assert status == 1
    assert "comma" in captured.err
    assert not any("volume create" in " ".join(argv) for argv in recorded)
    assert "bad,password" not in captured.out + captured.err
    assert setup_remote_test_volume.password_rejection_reason("fine") is None


def test_create_verifies_then_rolls_back_on_a_failed_mount(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (1, ABSENT_ERROR),
            "dst=/probe": (1, "docker: Error response from daemon: permission denied"),
            "--privileged": [
                (0, "[1.0] older line"),
                (
                    0,
                    "[1.0] older line\n"
                    "[2.0] CIFS: VFS: Status code returned 0xc000006d NT_STATUS_LOGON_FAILURE",
                ),
            ],
        },
    )
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess, "run", lambda command, **kwargs: None
    )

    status = setup_remote_test_volume.main(["--kernel-diagnosis"])
    captured = capsys.readouterr()

    assert status == 1
    joined = [" ".join(argv) for argv in recorded]
    probe_index = next(index for index, call in enumerate(joined) if "dst=/probe" in call)
    kernel_index = next(
        index
        for index, call in enumerate(joined)
        if "--privileged" in call and index > probe_index
    )
    remove_index = next(index for index, call in enumerate(joined) if "volume rm" in call)
    assert probe_index < kernel_index < remove_index
    assert "permission denied" in captured.err
    assert "0xc000006d" in captured.err
    assert "LOGON_FAILURE" in captured.err
    assert "not left persisted" in captured.err


def test_create_keeps_the_volume_when_the_probe_succeeds(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch, {"volume inspect": (1, ABSENT_ERROR), "dst=/probe": (0, "mount-ok\n")}
    )
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess, "run", lambda command, **kwargs: None
    )

    status = setup_remote_test_volume.main([])
    printed = capsys.readouterr().out

    assert status == 0
    assert "mount-ok" in printed
    assert not any("volume rm" in " ".join(argv) for argv in recorded)


def test_no_verify_skips_the_probe_entirely(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(monkeypatch, {"volume inspect": (1, ABSENT_ERROR)})
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess, "run", lambda command, **kwargs: None
    )

    status = setup_remote_test_volume.main(["--no-verify"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "verification skipped" in printed
    assert not any("dst=/probe" in " ".join(argv) for argv in recorded)


def test_status_probes_the_existing_volume_without_removing_it(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (0, INSPECT_PAYLOAD),
            "dst=/probe": (1, "permission denied"),
            "--privileged": [
                (0, "[1.0] older line"),
                (
                    0,
                    "[1.0] older line\n"
                    "[2.0] CIFS: Status code returned 0xc000006e ACCOUNT_RESTRICTION",
                ),
            ],
        },
    )

    status = setup_remote_test_volume.main(["--status", "--kernel-diagnosis"])
    captured = capsys.readouterr()

    assert status == 1
    assert "ACCOUNT_RESTRICTION" in captured.err
    assert not any("volume rm" in " ".join(argv) for argv in recorded)


def test_sharing_account_has_no_committed_default() -> None:
    assert setup_remote_test_volume.DEFAULT_USER == ""
    configuration = setup_remote_test_volume.load_remote_configuration()
    assert configuration["D810_REMOTE_SMB_USER"] == "share-account"


def test_logon_failure_wording_does_not_claim_a_stale_password() -> None:
    meaning = setup_remote_test_volume.explain_status_code("0xc000006d")

    assert "authentication or account identity rejected" in meaning
    assert "stale" not in meaning.lower()
    assert "hash exists" in meaning


@pytest.mark.parametrize("mode", [[], ["--status"], ["--remove"]])
def test_indeterminate_inspect_never_reports_absence(
    mode: list[str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ssh or daemon failure is not evidence that the volume is gone."""
    recorded = _fake_capture(monkeypatch, {"volume inspect": (1, SSH_ERROR)})

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not act on an indeterminate inspect")

    monkeypatch.setattr(setup_remote_test_volume.getpass, "getpass", _fail)

    status = setup_remote_test_volume.main(mode)
    captured = capsys.readouterr()

    assert status == setup_remote_test_volume.EXIT_INDETERMINATE
    assert "cannot determine" in captured.err
    assert "ssh: connect to host" in captured.err
    assert "absent" not in captured.out
    assert not any("volume rm" in " ".join(argv) for argv in recorded)


def test_indeterminate_container_listing_never_assumes_empty(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {"volume inspect": (0, INSPECT_PAYLOAD), "ps -a": (1, SSH_ERROR)},
    )

    status = setup_remote_test_volume.main(["--remove"])
    captured = capsys.readouterr()

    assert status == setup_remote_test_volume.EXIT_INDETERMINATE
    assert "cannot determine which containers" in captured.err
    assert not any("volume rm" in " ".join(argv) for argv in recorded)


def test_failed_rollback_reports_that_the_credential_survives(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(
        monkeypatch,
        {
            "volume inspect": (1, ABSENT_ERROR),
            "dst=/probe": (1, "permission denied"),
            "volume rm": (1, "Error response from daemon: volume is in use"),
        },
    )
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess, "run", lambda command, **kwargs: None
    )

    status = setup_remote_test_volume.main([])
    captured = capsys.readouterr()

    assert status == setup_remote_test_volume.EXIT_ROLLBACK_FAILED
    assert "VOLUME STILL EXISTS with the stored credential" in captured.err
    assert "volume is in use" in captured.err
    assert "--remove" in captured.err


def test_successful_rollback_keeps_the_mount_failure_exit_code(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(
        monkeypatch,
        {
            "volume inspect": (1, ABSENT_ERROR),
            "dst=/probe": (1, "permission denied"),
            "volume rm": (0, ""),
        },
    )
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    monkeypatch.setattr(
        setup_remote_test_volume.subprocess, "run", lambda command, **kwargs: None
    )

    status = setup_remote_test_volume.main([])
    captured = capsys.readouterr()

    assert status == setup_remote_test_volume.EXIT_MOUNT_FAILED
    assert "not left persisted" in captured.err
    assert "VOLUME STILL EXISTS" not in captured.err


def test_absent_volume_error_classification() -> None:
    assert setup_remote_test_volume.is_absent_volume_error(ABSENT_ERROR)
    assert not setup_remote_test_volume.is_absent_volume_error(SSH_ERROR)


def test_retained_volume_listing_targets_only_supported_roles() -> None:
    """A future d810.role value must never become a purge target by default."""
    digest = setup_remote_test_volume.share_root_digest("/srv/project")

    assert setup_remote_test_volume.build_retained_volume_list_argvs(
        remote="h", volume="idapro", share_root="/srv/project"
    ) == [
        [
            "docker", "-H", "ssh://h", "volume", "ls",
            "--filter", "label=d810.role=work",
            "--filter", "label=d810.credential_volume=idapro",
            "--filter", f"label=d810.share_root_digest={digest}",
            "--format", "{{.Name}}",
        ],
        [
            "docker", "-H", "ssh://h", "volume", "ls",
            "--filter", "label=d810.role=cobra-cache",
            "--filter", "label=d810.credential_volume=idapro",
            "--filter", f"label=d810.share_root_digest={digest}",
            "--format", "{{.Name}}",
        ],
    ]
    assert setup_remote_test_volume.share_root_digest("/other") != digest


def test_orphaned_work_volumes_are_reachable_without_the_credential_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (1, ABSENT_ERROR),
            "label=d810.role": (0, "d810-work-orphan-0011aabb\n"),
        },
    )

    status = setup_remote_test_volume.main(["--remove", "--purge-work-volumes"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "already absent" in printed
    assert "purged retained runner volume d810-work-orphan-0011aabb" in printed
    assert any(
        "volume rm d810-work-orphan-0011aabb" in " ".join(argv) for argv in recorded
    )


def test_purge_never_touches_another_credential_volumes_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selection happens in docker's filter, so foreign copies are never listed."""
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (1, ABSENT_ERROR),
            "label=d810.credential_volume=other": (0, ""),
        },
    )

    status = setup_remote_test_volume.main(
        ["--remove", "--purge-work-volumes", "--volume", "other"]
    )

    assert status == 0
    listing = [
        " ".join(argv) for argv in recorded if "label=d810.role" in " ".join(argv)
    ]
    assert listing and all(
        "label=d810.credential_volume=other" in call for call in listing
    )
    assert not any("volume rm d810-work" in " ".join(argv) for argv in recorded)


def test_dry_run_shows_the_exact_work_volume_filter(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fail(argv):
        raise AssertionError("--dry-run must not run docker")

    for seam in ("run_capture", "run_probe"):
        monkeypatch.setattr(setup_remote_test_volume, seam, _fail)

    assert setup_remote_test_volume.main(["--remove", "--dry-run"]) == 0
    printed = capsys.readouterr().out
    assert "--filter label=d810.role" in printed
    assert "--filter label=d810.credential_volume=idapro" in printed
    assert "--filter label=d810.share_root_digest=" in printed


def test_status_enumerates_retained_work_volumes(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(
        monkeypatch,
        {
            "volume inspect": (0, INSPECT_PAYLOAD),
            "label=d810.role": (0, "d810-work-wt-0011aabb\nd810-work-other-22ccddee\n"),
            "dst=/probe": (0, "mount-ok"),
        },
    )

    status = setup_remote_test_volume.main(["--status"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "retained runner volumes (source + CoBRA cache):" in printed
    assert "d810-work-wt-0011aabb" in printed
    assert "d810-work-other-22ccddee" in printed


def test_remove_keeps_work_volumes_unless_purge_is_requested(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (0, INSPECT_PAYLOAD),
            "label=d810.role": (0, "d810-work-wt-0011aabb\n"),
        },
    )

    status = setup_remote_test_volume.main(["--remove"])
    printed = capsys.readouterr().out

    assert status == 0
    assert "d810-work-wt-0011aabb" in printed
    assert "--purge-work-volumes" in printed
    assert not any(
        "volume rm d810-work" in " ".join(argv) for argv in recorded
    )


def test_purge_removes_every_work_volume(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (0, INSPECT_PAYLOAD),
            "label=d810.role": (0, "d810-work-a-0011aabb\nd810-work-b-22ccddee\n"),
        },
    )

    status = setup_remote_test_volume.main(["--remove", "--purge-work-volumes"])
    printed = capsys.readouterr().out

    assert status == 0
    joined = [" ".join(argv) for argv in recorded]
    assert any("volume rm d810-work-a-0011aabb" in call for call in joined)
    assert any("volume rm d810-work-b-22ccddee" in call for call in joined)
    assert printed.count("purged retained runner volume") == 2


def test_purge_handles_each_supported_role_and_not_an_unknown_role(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(
        monkeypatch,
        {
            "volume inspect": (1, ABSENT_ERROR),
            "label=d810.role=work": (0, "d810-work-a-0011aabb\nshared\n"),
            "label=d810.role=cobra-cache": (0, "d810-cobra-a-0011aabb\nshared\n"),
        },
    )

    status = setup_remote_test_volume.main(["--remove", "--purge-work-volumes"])
    printed = capsys.readouterr().out

    assert status == 0
    joined = [" ".join(argv) for argv in recorded]
    listings = [call for call in joined if "volume ls" in call]
    assert len(listings) == 2
    assert all("--filter label=d810.role " not in call for call in listings)
    assert {"label=d810.role=work", "label=d810.role=cobra-cache"} == {
        next(token for token in call.split() if token.startswith("label=d810.role="))
        for call in listings
    }
    assert any("volume rm d810-work-a-0011aabb" in call for call in joined)
    assert any("volume rm d810-cobra-a-0011aabb" in call for call in joined)
    assert sum("volume rm shared" in call for call in joined) == 1
    assert not any("future-role" in call for call in joined)
    assert "retained runner volumes (source + CoBRA cache)" in printed


@pytest.mark.parametrize("failing_role", ["work", "cobra-cache"])
def test_purge_aborts_without_removing_any_retained_volume_when_a_role_query_fails(
    failing_role: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = {
        "volume inspect": (1, ABSENT_ERROR),
        "label=d810.role=work": (
            (1, SSH_ERROR)
            if failing_role == "work"
            else (0, "d810-work-a-0011aabb\n")
        ),
        "label=d810.role=cobra-cache": (
            (1, SSH_ERROR)
            if failing_role == "cobra-cache"
            else (0, "d810-cobra-a-0011aabb\n")
        ),
    }
    recorded = _fake_capture(monkeypatch, responses)

    status = setup_remote_test_volume.main(["--remove", "--purge-work-volumes"])

    assert status == setup_remote_test_volume.EXIT_INDETERMINATE
    assert not any("volume rm d810-" in " ".join(argv) for argv in recorded)
    assert "cannot determine which retained runner volumes" in capsys.readouterr().err


def test_purge_never_selects_a_future_role_offered_to_a_key_only_selector(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[list[str]] = []

    def _capture(argv: list[str]) -> tuple[int, str]:
        command = list(argv)
        recorded.append(command)
        if command[3:6] == ["volume", "inspect", "idapro"]:
            return 1, ABSENT_ERROR
        if command[3:6] == ["volume", "ls", "--filter"]:
            role = command[6]
            if role == "label=d810.role":
                return 0, "d810-future-role-a-0011aabb\n"
            if role == "label=d810.role=work":
                return 0, "d810-work-a-0011aabb\n"
            if role == "label=d810.role=cobra-cache":
                return 0, "d810-cobra-a-0011aabb\n"
        return 0, ""

    monkeypatch.setattr(setup_remote_test_volume, "run_capture", _capture)

    status = setup_remote_test_volume.main(["--remove", "--purge-work-volumes"])
    printed = capsys.readouterr().out

    assert status == 0
    joined = [" ".join(argv) for argv in recorded]
    assert any("volume rm d810-work-a-0011aabb" in call for call in joined)
    assert any("volume rm d810-cobra-a-0011aabb" in call for call in joined)
    assert not any("d810-future-role" in call for call in joined)
    assert "d810-future-role" not in printed


def test_work_volume_listing_failure_is_indeterminate(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_capture(
        monkeypatch,
        {
            "volume inspect": (0, INSPECT_PAYLOAD),
            "dst=/probe": (0, "mount-ok"),
            "label=d810.role": (1, SSH_ERROR),
        },
    )

    status = setup_remote_test_volume.main(["--status"])

    assert status == setup_remote_test_volume.EXIT_INDETERMINATE
    assert "cannot determine which retained runner volumes" in capsys.readouterr().err


def test_doctests_pass() -> None:
    import doctest

    results = doctest.testmod(setup_remote_test_volume, verbose=False)
    assert results.failed == 0, results


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", []),
        ("noperm", ["noperm"]),
        (" cache=none , actimeo=0 ", ["cache=none", "actimeo=0"]),
        ("cache=none,actimeo=0", ["cache=none", "actimeo=0"]),
    ],
)
def test_valid_mount_option_tokens(raw: str, expected: list[str]) -> None:
    assert setup_remote_test_volume.validate_mount_options(raw) == expected


@pytest.mark.parametrize(
    "raw,fragment",
    [
        ("password=x", "must not set password"),
        ("pass=x", "must not set password"),
        ("username=root", "must not set username"),
        ("user=root", "must not set username"),
        ("nobrl", "must not set nobrl"),
        ("nolock", "must not set nolock"),
        ("cache=none,nobrl", "must not set nobrl"),
        ("SEC=ntlmv2", "invalid cifs option token"),
        ("no brl", "invalid cifs option token"),
        ("vers=3.0;rm -rf /", "invalid cifs option token"),
    ],
)
def test_rejected_mount_option_tokens(raw: str, fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        setup_remote_test_volume.validate_mount_options(raw)


def test_mount_opts_are_appended_to_the_option_string() -> None:
    identity = {"share": "//files.example/project", "user": "share-account"}
    options = setup_remote_test_volume.build_mount_options(
        "pw", extra_options="cache=none", **identity
    )

    assert options.endswith(",dir_mode=0700,cache=none")
    assert setup_remote_test_volume.build_mount_options("pw", **identity).endswith(
        "dir_mode=0700"
    )


def test_mount_opts_are_reported_and_kept_out_of_the_credential(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )
    for seam in ("run_capture", "run_probe"):
        monkeypatch.setattr(setup_remote_test_volume, seam, lambda argv: (0, ""))

    status = setup_remote_test_volume.main(
        ["--dry-run", "--mount-opts", "cache=none,noperm"]
    )
    printed = capsys.readouterr().out

    assert status == 0
    assert "extra cifs options: cache=none,noperm" in printed
    assert "dir_mode=0700,cache=none,noperm" in printed
    assert "hunter2" not in printed


def test_nobrl_is_refused_because_staging_replaces_it(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remote runs never write SQLite on this mount, so disabling locking is wrong."""
    recorded = _fake_capture(monkeypatch, {"volume inspect": (1, ABSENT_ERROR)})
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("nobrl must never reach docker volume create")

    monkeypatch.setattr(setup_remote_test_volume.subprocess, "run", _fail)

    status = setup_remote_test_volume.main(["--mount-opts", "nobrl"])
    captured = capsys.readouterr()

    assert status == 1
    assert "must not set nobrl" in captured.err
    assert "work volume" in captured.err
    assert not any("volume create" in " ".join(argv) for argv in recorded)


def test_invalid_mount_opts_fail_before_creating_anything(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = _fake_capture(monkeypatch, {"volume inspect": (1, ABSENT_ERROR)})
    monkeypatch.setattr(
        setup_remote_test_volume.getpass, "getpass", lambda prompt: "hunter2"
    )

    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid options must not reach docker volume create")

    monkeypatch.setattr(setup_remote_test_volume.subprocess, "run", _fail)

    status = setup_remote_test_volume.main(["--mount-opts", "password=leak"])
    captured = capsys.readouterr()

    assert status == 1
    assert "must not set password" in captured.err
    assert not any("volume create" in " ".join(argv) for argv in recorded)
