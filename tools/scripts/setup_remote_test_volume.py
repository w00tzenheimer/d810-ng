#!/usr/bin/env python3
"""Create the SMB-backed Docker volume that ``--remote`` system test runs use.

The remote Linux engine reaches this Mac's checkout through one CIFS volume, so
the volume has to exist before ``run_system_tests_docker.sh --remote HOST`` can
mount anything.  Creating it needs an SMB password, which is why this is a
one-time manual step rather than something the runner does implicitly.

The password is passed to ``docker volume create`` as a mount option, so it is
stored in the volume's options and is visible to ``docker volume inspect`` on
the remote host.  That is the accepted trade for typing it once; remove it with
``docker volume rm <volume>``.

The helper also undoes itself: ``--status`` shows what exists (with the stored
password redacted) and what still references the volume, ``--remove`` deletes
the volume and with it the stored credential.

Examples::

    python3 tools/scripts/setup_remote_test_volume.py --dry-run
    python3 tools/scripts/setup_remote_test_volume.py --remote remote-engine.example
    python3 tools/scripts/setup_remote_test_volume.py --status
    python3 tools/scripts/setup_remote_test_volume.py --remove [--force]
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import subprocess
import sys
from typing import Sequence

DEFAULT_REMOTE = "remote-engine.example"
DEFAULT_VOLUME = "idapro"
DEFAULT_SHARE = "//smb-server.example/idapro"
DEFAULT_USER = "smbuser"
DEFAULT_VERSION = "3.0"
DEFAULT_UID = "0"
DEFAULT_GID = "0"
DEFAULT_FILE_MODE = "0700"
DEFAULT_DIR_MODE = "0700"
REDACTION = "********"
PASSWORD_OPTION_PATTERN = re.compile(r"(?<=password=)[^,]*")
CONTAINER_FORMAT = "{{.ID}} {{.Status}} {{.Names}}"
PROBE_IMAGE = "alpine"
PROBE_COMMAND = "ls /probe >/dev/null && echo mount-ok"
KERNEL_STATUS_COMMAND = 'dmesg | grep -E "CIFS: Status code" | tail -1'
STATUS_CODE_MEANINGS = {
    "0xc000006d": (
        "STATUS_LOGON_FAILURE: the password (or its NT hash) does not match. "
        "Re-tick the account under File Sharing > Options, re-enter the password, "
        "then re-run with --recreate."
    ),
    "0xc000006e": (
        "STATUS_ACCOUNT_RESTRICTION: the account is refused for this logon type "
        "(this is what a disabled guest account returns)."
    ),
    "0xc00000cc": (
        "STATUS_BAD_NETWORK_NAME: the share name in device=//HOST/SHARE is wrong."
    ),
}
LOCK_REMINDER = (
    "Per-worktree run locks are released by the runner's EXIT trap; a stale one is "
    "removed with: rmdir <worktree>/.tmp/remote-run.lock"
)


def share_host(share: str) -> str:
    """Return the server component of an SMB share path.

    >>> share_host("//smb-server.example/idapro")
    'smb-server.example'
    """
    stripped = share.lstrip("/")
    host = stripped.split("/", 1)[0]
    if not host:
        raise ValueError(f"share must look like //HOST/NAME, got {share!r}")
    return host


def build_mount_options(
    password: str,
    *,
    share: str = DEFAULT_SHARE,
    user: str = DEFAULT_USER,
    version: str = DEFAULT_VERSION,
    uid: str = DEFAULT_UID,
    gid: str = DEFAULT_GID,
    file_mode: str = DEFAULT_FILE_MODE,
    dir_mode: str = DEFAULT_DIR_MODE,
) -> str:
    """Build the ``o=`` value handed to the local volume driver.

    Every option here is an in-kernel cifs option: docker's local driver calls
    ``mount(2)`` directly, so userspace-only ``mount.cifs`` options such as
    ``credentials=`` would not work.

    >>> build_mount_options("pw")
    'addr=smb-server.example,username=smbuser,password=pw,vers=3.0,uid=0,gid=0,file_mode=0700,dir_mode=0700'
    """
    return ",".join(
        [
            f"addr={share_host(share)}",
            f"username={user}",
            f"password={password}",
            f"vers={version}",
            f"uid={uid}",
            f"gid={gid}",
            f"file_mode={file_mode}",
            f"dir_mode={dir_mode}",
        ]
    )


def build_volume_argv(
    *,
    remote: str,
    volume: str,
    share: str,
    options: str,
) -> list[str]:
    """Build the full ``docker volume create`` argv.

    >>> build_volume_argv(
    ...     remote="h", volume="v", share="//s/x", options="o"
    ... )[:5]
    ['docker', '-H', 'ssh://h', 'volume', 'create']
    """
    return [
        "docker",
        "-H",
        f"ssh://{remote}",
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=cifs",
        "--opt",
        f"device={share}",
        "--opt",
        f"o={options}",
        volume,
    ]


def redact_argv(argv: Sequence[str], password: str) -> list[str]:
    """Replace every occurrence of the password so argv is safe to print.

    An empty password would otherwise match everywhere, so it is left alone.

    >>> redact_argv(["o=password=hunter2,vers=3.0"], "hunter2")
    ['o=password=********,vers=3.0']
    >>> redact_argv(["o=password=,vers=3.0"], "")
    ['o=password=,vers=3.0']
    """
    if not password:
        return list(argv)
    return [argument.replace(password, REDACTION) for argument in argv]


def build_inspect_argv(*, remote: str, volume: str) -> list[str]:
    """Build the ``docker volume inspect`` argv.

    >>> build_inspect_argv(remote="h", volume="v")
    ['docker', '-H', 'ssh://h', 'volume', 'inspect', 'v']
    """
    return ["docker", "-H", f"ssh://{remote}", "volume", "inspect", volume]


def build_container_filter_argv(*, remote: str, volume: str) -> list[str]:
    """Build the argv that lists containers still referencing the volume.

    >>> build_container_filter_argv(remote="h", volume="v")[3:7]
    ['ps', '-a', '--filter', 'volume=v']
    """
    return [
        "docker",
        "-H",
        f"ssh://{remote}",
        "ps",
        "-a",
        "--filter",
        f"volume={volume}",
        "--format",
        CONTAINER_FORMAT,
    ]


def build_remove_volume_argv(*, remote: str, volume: str) -> list[str]:
    """Build the ``docker volume rm`` argv.

    >>> build_remove_volume_argv(remote="h", volume="v")
    ['docker', '-H', 'ssh://h', 'volume', 'rm', 'v']
    """
    return ["docker", "-H", f"ssh://{remote}", "volume", "rm", volume]


def build_remove_containers_argv(*, remote: str, container_ids: Sequence[str]) -> list[str]:
    """Build the ``docker rm -f`` argv for leftover containers.

    >>> build_remove_containers_argv(remote="h", container_ids=["a", "b"])
    ['docker', '-H', 'ssh://h', 'rm', '-f', 'a', 'b']
    """
    if not container_ids:
        raise ValueError("no containers to remove")
    return ["docker", "-H", f"ssh://{remote}", "rm", "-f", *container_ids]


def redact_options(options: str) -> str:
    """Hide the password inside a stored ``o=`` option string.

    ``docker volume inspect`` returns the credential in cleartext; nothing here
    ever prints it.

    >>> redact_options("addr=h,username=u,password=hunter2,vers=3.0")
    'addr=h,username=u,password=********,vers=3.0'
    >>> redact_options("addr=h,vers=3.0")
    'addr=h,vers=3.0'
    """
    return PASSWORD_OPTION_PATTERN.sub(REDACTION, options)


def parse_container_lines(output: str) -> list[str]:
    r"""Split ``docker ps`` output into non-empty container lines.

    >>> parse_container_lines("abc Up 2 min name\n\n")
    ['abc Up 2 min name']
    >>> parse_container_lines("")
    []
    """
    return [line.strip() for line in output.splitlines() if line.strip()]


def removal_decision(containers: Sequence[str], force: bool) -> str:
    """Decide what to do about containers pinning the volume.

    >>> removal_decision([], False)
    'proceed'
    >>> removal_decision(["abc Exited name"], False)
    'refuse'
    >>> removal_decision(["abc Exited name"], True)
    'force'
    """
    if not containers:
        return "proceed"
    return "force" if force else "refuse"


def format_status(inspect_output: str, container_output: str) -> str:
    """Render ``volume inspect`` for humans, with the password redacted.

    >>> print(format_status(
    ...     '[{"Driver": "local", "Options": {"device": "//h/s",'
    ...     ' "o": "username=u,password=pw", "type": "cifs"}}]', ""))
    driver:  local
    device:  //h/s
    type:    cifs
    options: username=u,password=********
    containers referencing the volume: none
    """
    try:
        payload = json.loads(inspect_output)
    except (ValueError, TypeError):
        payload = []
    entry = payload[0] if isinstance(payload, list) and payload else {}
    options = entry.get("Options") or {}
    lines = [
        f"driver:  {entry.get('Driver', 'unknown')}",
        f"device:  {options.get('device', 'unknown')}",
        f"type:    {options.get('type', 'unknown')}",
        f"options: {redact_options(options.get('o', ''))}",
    ]
    containers = parse_container_lines(container_output)
    if containers:
        lines.append("containers referencing the volume:")
        lines.extend(f"  {line}" for line in containers)
    else:
        lines.append("containers referencing the volume: none")
    return "\n".join(lines)


def build_verify_probe_argv(
    *, remote: str, volume: str, image: str = PROBE_IMAGE
) -> list[str]:
    """Build the read-only probe that proves the volume actually mounts.

    >>> build_verify_probe_argv(remote="h", volume="v")[3:8]
    ['run', '--rm', '--mount', 'type=volume,src=v,dst=/probe,readonly', 'alpine']
    """
    return [
        "docker",
        "-H",
        f"ssh://{remote}",
        "run",
        "--rm",
        "--mount",
        f"type=volume,src={volume},dst=/probe,readonly",
        image,
        "sh",
        "-c",
        PROBE_COMMAND,
    ]


def build_kernel_status_argv(*, remote: str, image: str = PROBE_IMAGE) -> list[str]:
    """Build the privileged dmesg read that names the real CIFS failure.

    ``permission denied`` from mount(2) is the same string for a wrong password,
    a disabled guest account and a wrong share name; only the kernel's status
    code separates them.

    >>> build_kernel_status_argv(remote="h")[3:6]
    ['run', '--rm', '--privileged']
    """
    return [
        "docker",
        "-H",
        f"ssh://{remote}",
        "run",
        "--rm",
        "--privileged",
        image,
        "sh",
        "-c",
        KERNEL_STATUS_COMMAND,
    ]


def password_rejection_reason(password: str) -> str | None:
    """Reject passwords that cannot survive the cifs option encoding.

    The ``o=`` value is a comma-separated list, so an embedded comma silently
    truncates or mis-parses the option string.

    >>> password_rejection_reason("good-pw") is None
    True
    >>> password_rejection_reason("a,b")
    'the SMB password contains a comma, which cifs mount options cannot encode'
    """
    if "," in password:
        return "the SMB password contains a comma, which cifs mount options cannot encode"
    return None


def explain_status_code(line: str) -> str:
    """Translate a kernel CIFS status line into an actionable sentence.

    >>> explain_status_code("CIFS: Status code returned 0xc000006d NT_STATUS_LOGON_FAILURE")
    'STATUS_LOGON_FAILURE: the password (or its NT hash) does not match. Re-tick the account under File Sharing > Options, re-enter the password, then re-run with --recreate.'
    >>> explain_status_code("nothing recognisable")
    'no known CIFS status code in the kernel log line'
    """
    lowered = line.lower()
    for code, meaning in STATUS_CODE_MEANINGS.items():
        if code in lowered:
            return meaning
    return "no known CIFS status code in the kernel log line"


def run_capture(argv: Sequence[str]) -> tuple[int, str]:
    """Run a docker command and capture stdout (impure seam for tests)."""
    completed = subprocess.run(
        list(argv), capture_output=True, text=True, check=False
    )
    return completed.returncode, completed.stdout


def run_probe(argv: Sequence[str]) -> tuple[int, str]:
    """Run a probe container, merging stderr (the daemon error lands there)."""
    completed = subprocess.run(
        list(argv), capture_output=True, text=True, check=False
    )
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--remote", default=DEFAULT_REMOTE, help="remote Docker engine host")
    parser.add_argument("--volume", default=DEFAULT_VOLUME, help="volume name to create")
    parser.add_argument("--share", default=DEFAULT_SHARE, help="SMB share, e.g. //smb-server.example/idapro")
    parser.add_argument("--user", default=DEFAULT_USER, help="SMB user")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the redacted docker argv instead of running it (all modes)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--status",
        action="store_true",
        help="show the volume (password redacted) and anything still referencing it",
    )
    mode.add_argument(
        "--remove",
        action="store_true",
        help="delete the volume, and with it the stored credential",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --remove: also `docker rm -f` containers that still reference the volume",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the read-only mount probe that verifies a created volume",
    )
    parser.add_argument(
        "--image",
        default=PROBE_IMAGE,
        help=f"image used for the mount/dmesg probes (default: {PROBE_IMAGE})",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="remove an existing volume before creating it (create mode refuses otherwise)",
    )
    return parser


def _verify_mount(arguments: argparse.Namespace) -> int:
    """Prove the volume mounts; on failure name the CIFS status code."""
    probe_argv = build_verify_probe_argv(
        remote=arguments.remote, volume=arguments.volume, image=arguments.image
    )
    status, output = run_probe(probe_argv)
    if status == 0:
        print(f"mount-ok: volume {arguments.volume} mounts on ssh://{arguments.remote}")
        return 0
    print(f"ERROR: volume {arguments.volume} does not mount:", file=sys.stderr)
    for line in output.strip().splitlines():
        print(f"       {line}", file=sys.stderr)
    _, kernel_output = run_probe(
        build_kernel_status_argv(remote=arguments.remote, image=arguments.image)
    )
    kernel_lines = [line.strip() for line in kernel_output.splitlines() if line.strip()]
    if kernel_lines:
        print(f"       kernel: {kernel_lines[-1]}", file=sys.stderr)
        print(f"       meaning: {explain_status_code(kernel_lines[-1])}", file=sys.stderr)
    else:
        print("       kernel: no CIFS status line found in the engine's dmesg", file=sys.stderr)
    return 1


def _status(arguments: argparse.Namespace) -> int:
    inspect_argv = build_inspect_argv(remote=arguments.remote, volume=arguments.volume)
    containers_argv = build_container_filter_argv(
        remote=arguments.remote, volume=arguments.volume
    )
    if arguments.dry_run:
        print(" ".join(inspect_argv))
        print(" ".join(containers_argv))
        if not arguments.no_verify:
            print(
                " ".join(
                    build_verify_probe_argv(
                        remote=arguments.remote,
                        volume=arguments.volume,
                        image=arguments.image,
                    )
                )
            )
        return 0
    status, inspect_output = run_capture(inspect_argv)
    if status != 0:
        print(f"volume {arguments.volume} is absent on ssh://{arguments.remote}")
        return 1
    _, container_output = run_capture(containers_argv)
    print(format_status(inspect_output, container_output))
    if arguments.no_verify:
        return 0
    # Read-only and non-destructive: --status never removes anything.
    return _verify_mount(arguments)


def _remove(arguments: argparse.Namespace) -> int:
    inspect_argv = build_inspect_argv(remote=arguments.remote, volume=arguments.volume)
    containers_argv = build_container_filter_argv(
        remote=arguments.remote, volume=arguments.volume
    )
    remove_argv = build_remove_volume_argv(
        remote=arguments.remote, volume=arguments.volume
    )
    if arguments.dry_run:
        print(" ".join(containers_argv))
        if arguments.force:
            print(f"docker -H ssh://{arguments.remote} rm -f <containers listed above>")
        print(" ".join(remove_argv))
        return 0

    status, _ = run_capture(inspect_argv)
    if status != 0:
        print(f"volume {arguments.volume} is already absent on ssh://{arguments.remote}")
        return 0

    _, container_output = run_capture(containers_argv)
    containers = parse_container_lines(container_output)
    decision = removal_decision(containers, arguments.force)
    if decision == "refuse":
        print(
            f"ERROR: {len(containers)} container(s) still reference volume {arguments.volume}:",
            file=sys.stderr,
        )
        for line in containers:
            print(f"       {line}", file=sys.stderr)
        print(
            "       The runner starts its containers with --rm, so a leftover means a crashed "
            "or killed run. Re-run with --force to `docker rm -f` them first.",
            file=sys.stderr,
        )
        return 1
    if decision == "force":
        identifiers = [line.split()[0] for line in containers]
        status, _ = run_capture(
            build_remove_containers_argv(
                remote=arguments.remote, container_ids=identifiers
            )
        )
        if status != 0:
            print(
                f"ERROR: could not remove containers {' '.join(identifiers)}",
                file=sys.stderr,
            )
            return status or 1

    status, _ = run_capture(remove_argv)
    if status != 0:
        print(
            f"ERROR: docker volume rm {arguments.volume} failed with exit status {status}",
            file=sys.stderr,
        )
        return status or 1
    print(
        f"removed volume {arguments.volume} from ssh://{arguments.remote}; "
        "the stored SMB credential is deleted with it"
    )
    print(LOCK_REMINDER)
    return 0


def _create(arguments: argparse.Namespace) -> int:
    if not arguments.dry_run:
        status, _ = run_capture(
            build_inspect_argv(remote=arguments.remote, volume=arguments.volume)
        )
        if status == 0:
            if not arguments.recreate:
                print(
                    f"ERROR: volume {arguments.volume} already exists on ssh://{arguments.remote}; "
                    "use --recreate to replace it or --remove to delete it",
                    file=sys.stderr,
                )
                return 1
            removal_status = _remove(arguments)
            if removal_status != 0:
                return removal_status
    elif arguments.recreate:
        print(" ".join(build_remove_volume_argv(remote=arguments.remote, volume=arguments.volume)))

    password = ""
    try:
        try:
            password = getpass.getpass(
                f"SMB password for {arguments.user}@{share_host(arguments.share)}: "
            )
        except (EOFError, KeyboardInterrupt):
            print("ERROR: no SMB password was entered", file=sys.stderr)
            return 1
        rejection = password_rejection_reason(password)
        if rejection is not None:
            print(f"ERROR: {rejection}", file=sys.stderr)
            return 1
        options = build_mount_options(
            password,
            share=arguments.share,
            user=arguments.user,
        )
        command = build_volume_argv(
            remote=arguments.remote,
            volume=arguments.volume,
            share=arguments.share,
            options=options,
        )
        printable = " ".join(redact_argv(command, password))
        print(printable)
        if arguments.dry_run:
            if not arguments.no_verify:
                print(
                    " ".join(
                        build_verify_probe_argv(
                            remote=arguments.remote,
                            volume=arguments.volume,
                            image=arguments.image,
                        )
                    )
                )
            return 0
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as error:
            print(
                f"ERROR: docker volume create failed with exit status {error.returncode}",
                file=sys.stderr,
            )
            return error.returncode or 1
        except OSError as error:
            print(f"ERROR: could not run docker: {error}", file=sys.stderr)
            return 1
        print(
            f"created volume {arguments.volume} on ssh://{arguments.remote}; "
            f"the password is visible to `docker volume inspect {arguments.volume}` there"
        )
        if arguments.no_verify:
            print("verification skipped (--no-verify); the credential is unproven")
            return 0
        if _verify_mount(arguments) != 0:
            run_capture(
                build_remove_volume_argv(
                    remote=arguments.remote, volume=arguments.volume
                )
            )
            print(
                f"removed volume {arguments.volume} again so an unusable credential "
                "is not left persisted on the remote host",
                file=sys.stderr,
            )
            return 1
        return 0
    finally:
        password = ""
        del password


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.status:
        return _status(arguments)
    if arguments.remove:
        return _remove(arguments)
    return _create(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
