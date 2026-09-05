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
SSH_ERROR = "error during connect: ssh: connect to host remote-engine.example port 22: refused"

INSPECT_PAYLOAD = (
    '[{"Name": "idapro", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/idapro/_data",'
    ' "Options": {"device": "//smb-server.example/idapro", "o":'
    ' "addr=smb-server.example,username=smbuser,password=hunter2,vers=3.0,uid=0,gid=0,'
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

    assert "hunter2" not in rendered
    assert "password=********" in rendered
    assert "driver:  local" in rendered
    assert "device:  //smb-server.example/idapro" in rendered
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


def test_default_user_is_the_sharing_account() -> None:
    assert setup_remote_test_volume.DEFAULT_USER == "smbuser"
    assert "username=smbuser" in setup_remote_test_volume.build_mount_options("pw")


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


def test_doctests_pass() -> None:
    import doctest

    results = doctest.testmod(setup_remote_test_volume, verbose=False)
    assert results.failed == 0, results
