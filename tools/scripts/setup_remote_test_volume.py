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
from pathlib import Path
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
EXIT_MOUNT_FAILED = 1
EXIT_ROLLBACK_FAILED = 2
EXIT_INDETERMINATE = 3
PASSWORD_OPTION_PATTERN = re.compile(r"(?<=password=)[^,]*")
CONTAINER_FORMAT = "{{.ID}} {{.Status}} {{.Names}}"
WORK_VOLUME_ROLE_LABEL = "d810.role=work"
DEFAULT_SHARE_ROOT = "/srv/share-root"
WORK_VOLUME_FORMAT = "{{.Name}}"
PROBE_IMAGE = "alpine"
# Reading the engine's kernel ring buffer needs --privileged, so the image is
# pinned by digest: an unpinned tag would be a fresh pull of mutable content
# into a privileged container.
KERNEL_PROBE_IMAGE = (
    "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
)
PROBE_COMMAND = "ls /probe >/dev/null && echo mount-ok"
KERNEL_DMESG_COMMAND = "dmesg"
STATUS_LINE_MARKER = "status code"
STATUS_CODE_MEANINGS = {
    "0xc000006d": (
        "STATUS_LOGON_FAILURE: authentication or account identity rejected for this "
        "share. A stored SMB-NT hash only proves a hash exists, not that these "
        "credentials are current or that this account is authorized here. Re-check "
        "the account and its share access, then re-run with --recreate."
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


def validate_mount_options(raw: str) -> list[str]:
    """Validate extra cifs options before they reach the option string.

    The value is spliced into a comma-separated list that also carries the
    credential, so each token is checked and the identity options are refused.

    >>> validate_mount_options("nobrl")
    ['nobrl']
    >>> validate_mount_options(" nobrl , noperm ")
    ['nobrl', 'noperm']
    >>> validate_mount_options("")
    []
    >>> validate_mount_options("password=x")
    Traceback (most recent call last):
    ValueError: --mount-opts must not set password
    >>> validate_mount_options("SEC=ntlmv2")
    Traceback (most recent call last):
    ValueError: invalid cifs option token: 'SEC=ntlmv2'
    """
    tokens: list[str] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        name = token.split("=", 1)[0]
        if name in ("password", "pass"):
            raise ValueError("--mount-opts must not set password")
        if name in ("username", "user"):
            raise ValueError("--mount-opts must not set username")
        if not re.fullmatch(r"[a-z0-9_=.]+", token):
            raise ValueError(f"invalid cifs option token: {token!r}")
        tokens.append(token)
    return tokens


def build_mount_options(
    password: str,
    *,
    extra_options: str = "",
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
            *validate_mount_options(extra_options),
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


def share_root_digest(share_root: str) -> str:
    """Short digest of the exported share root, as the runner labels it.

    >>> share_root_digest("/srv/share-root")[:2].isalnum()
    True
    >>> len(share_root_digest("/x"))
    8
    """
    import hashlib

    return hashlib.sha256(share_root.encode()).hexdigest()[:8]


def build_work_volume_list_argv(
    *, remote: str, volume: str, share_root: str
) -> list[str]:
    """List the source-copy volumes belonging to THIS credential volume.

    Selecting every ``d810.role=work`` volume on the engine would sweep in the
    copies of an unrelated share or credential, so the role label alone is not
    a safe selector.

    Both roles the runner retains (the source copy and the CoBRA build cache)
    are matched, because both hold state on the engine.

    >>> build_work_volume_list_argv(remote="h", volume="v", share_root="/x")[3:6]
    ['volume', 'ls', '--filter']
    >>> "label=d810.credential_volume=v" in build_work_volume_list_argv(
    ...     remote="h", volume="v", share_root="/x")
    True
    """
    return [
        "docker",
        "-H",
        f"ssh://{remote}",
        "volume",
        "ls",
        "--filter",
        "label=d810.role",
        "--filter",
        f"label=d810.credential_volume={volume}",
        "--filter",
        f"label=d810.share_root_digest={share_root_digest(share_root)}",
        "--format",
        WORK_VOLUME_FORMAT,
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


def build_kernel_dmesg_argv(
    *, remote: str, image: str = KERNEL_PROBE_IMAGE
) -> list[str]:
    """Build the privileged dmesg read used for before/after diagnosis.

    ``permission denied`` from mount(2) is the same string for rejected
    credentials, a restricted account and a wrong share name; only the kernel's
    status code separates them. The ring buffer is global to the engine, so the
    caller must diff two captures instead of trusting its tail.

    >>> build_kernel_dmesg_argv(remote="h")[3:6]
    ['run', '--rm', '--privileged']
    >>> build_kernel_dmesg_argv(remote="h")[6].startswith("alpine@sha256:")
    True
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
        KERNEL_DMESG_COMMAND,
    ]


def dmesg_status_delta(before: str, after: str) -> list[str]:
    r"""Return CIFS status lines that appeared between two dmesg captures.

    Only lines absent from the first capture are attributed to this probe;
    kernel timestamps make each line unique in practice.

    >>> dmesg_status_delta(
    ...     "[1.0] CIFS: Status code returned 0xc000006e OLD",
    ...     "[1.0] CIFS: Status code returned 0xc000006e OLD\n"
    ...     "[2.0] CIFS: Status code returned 0xc000006d NEW")
    ['[2.0] CIFS: Status code returned 0xc000006d NEW']
    >>> dmesg_status_delta("x", "x")
    []
    """
    seen = set(line.strip() for line in before.splitlines())
    return [
        line.strip()
        for line in after.splitlines()
        if line.strip() and line.strip() not in seen
        and STATUS_LINE_MARKER in line.lower()
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

    >>> explain_status_code(
    ...     "CIFS: Status code returned 0xc000006d LOGON_FAILURE").startswith(
    ...     "STATUS_LOGON_FAILURE: authentication or account identity rejected")
    True
    >>> explain_status_code("nothing recognisable")
    'no known CIFS status code in the kernel log line'
    """
    lowered = line.lower()
    for code, meaning in STATUS_CODE_MEANINGS.items():
        if code in lowered:
            return meaning
    return "no known CIFS status code in the kernel log line"


def is_absent_volume_error(output: str) -> bool:
    """Only the daemon's own "no such volume" text means absent.

    Any other failure (ssh down, daemon unreachable, permission) must not be
    reported as absence.

    >>> is_absent_volume_error("Error response from daemon: get idapro: no such volume")
    True
    >>> is_absent_volume_error("error during connect: ssh: connect to host ... refused")
    False
    """
    return "no such volume" in output.lower()


def run_capture(argv: Sequence[str]) -> tuple[int, str]:
    """Run a docker command and capture stdout (impure seam for tests)."""
    completed = subprocess.run(
        list(argv), capture_output=True, text=True, check=False
    )
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


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
    parser.add_argument(
        "--mount-opts",
        default="",
        help=(
            "extra cifs mount options appended verbatim to o= (comma-separated, "
            "e.g. nobrl). Credentials cannot be set this way."
        ),
    )
    parser.add_argument(
        "--share-root",
        default=DEFAULT_SHARE_ROOT,
        help=(
            "host directory the share exports; selects which work volumes belong "
            f"to this share (default: {DEFAULT_SHARE_ROOT})"
        ),
    )
    parser.add_argument(
        "--user",
        default=DEFAULT_USER,
        help=f"SMB user (default: {DEFAULT_USER}; override e.g. --user smbuser)",
    )
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
        "--purge-work-volumes",
        action="store_true",
        help="with --remove: also delete the retained per-worktree source copies",
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
        "--kernel-diagnosis",
        action="store_true",
        help=(
            "on a failed mount probe, read the engine's kernel log before and after "
            "to name the CIFS status code (starts a privileged container)"
        ),
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


def _inspect_volume(arguments: argparse.Namespace) -> tuple[str, str]:
    """Return ("present"|"absent"|"unknown", output) for the volume."""
    status, output = run_capture(
        build_inspect_argv(remote=arguments.remote, volume=arguments.volume)
    )
    if status == 0:
        return "present", output
    if is_absent_volume_error(output):
        return "absent", output
    return "unknown", output


def _report_indeterminate(what: str, output: str) -> int:
    print(f"ERROR: cannot determine {what}:", file=sys.stderr)
    for line in output.strip().splitlines():
        print(f"       {line}", file=sys.stderr)
    return EXIT_INDETERMINATE


def format_work_volumes(volumes: Sequence[str]) -> str:
    """Render the retained per-worktree source copies.

    >>> print(format_work_volumes([]))
    retained work volumes (source copies): none
    >>> print(format_work_volumes(["d810-work-wt-0011aabb"]))
    retained work volumes (source copies):
      d810-work-wt-0011aabb
    """
    if not volumes:
        return "retained work volumes (source copies): none"
    return "retained work volumes (source copies):\n" + "\n".join(
        f"  {name}" for name in volumes
    )


def _list_work_volumes(arguments: argparse.Namespace) -> tuple[bool, list[str], str]:
    """List retained work volumes; never assume none on error."""
    status, output = run_capture(
        build_work_volume_list_argv(
            remote=arguments.remote,
            volume=arguments.volume,
            share_root=arguments.share_root,
        )
    )
    if status != 0:
        return False, [], output
    return True, parse_container_lines(output), output


def _list_containers(arguments: argparse.Namespace) -> tuple[bool, list[str], str]:
    """List containers referencing the volume; never assume empty on error."""
    status, output = run_capture(
        build_container_filter_argv(remote=arguments.remote, volume=arguments.volume)
    )
    if status != 0:
        return False, [], output
    return True, parse_container_lines(output), output


def _verify_mount(arguments: argparse.Namespace) -> int:
    """Prove the volume mounts; optionally attribute the kernel status code."""
    kernel_before = ""
    if arguments.kernel_diagnosis:
        _, kernel_before = run_probe(
            build_kernel_dmesg_argv(remote=arguments.remote)
        )
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
    if not arguments.kernel_diagnosis:
        print(
            "       mount(2) reports every rejection as the same text; re-run with "
            "--kernel-diagnosis to read the engine's CIFS status code (starts a "
            "privileged container).",
            file=sys.stderr,
        )
        return 1
    _, kernel_after = run_probe(build_kernel_dmesg_argv(remote=arguments.remote))
    new_lines = dmesg_status_delta(kernel_before, kernel_after)
    if not new_lines:
        print(
            "       kernel: no new CIFS status line appeared during this probe "
            "(nothing can be attributed to it)",
            file=sys.stderr,
        )
        return 1
    for line in new_lines:
        print(f"       kernel: {line}", file=sys.stderr)
        print(f"       meaning: {explain_status_code(line)}", file=sys.stderr)
    return 1


def _status(arguments: argparse.Namespace) -> int:
    inspect_argv = build_inspect_argv(remote=arguments.remote, volume=arguments.volume)
    containers_argv = build_container_filter_argv(
        remote=arguments.remote, volume=arguments.volume
    )
    if arguments.dry_run:
        print(" ".join(inspect_argv))
        print(" ".join(containers_argv))
        print(
            " ".join(
                build_work_volume_list_argv(
                    remote=arguments.remote,
                    volume=arguments.volume,
                    share_root=arguments.share_root,
                )
            )
        )
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
    presence, inspect_output = _inspect_volume(arguments)
    if presence == "unknown":
        return _report_indeterminate(
            f"whether volume {arguments.volume} exists on ssh://{arguments.remote}",
            inspect_output,
        )
    if presence == "absent":
        print(f"volume {arguments.volume} is absent on ssh://{arguments.remote}")
        return 1
    listed, _containers, container_output = _list_containers(arguments)
    if not listed:
        return _report_indeterminate(
            f"which containers reference volume {arguments.volume}", container_output
        )
    print(format_status(inspect_output, container_output))
    listed, work_volumes, work_output = _list_work_volumes(arguments)
    if not listed:
        return _report_indeterminate("which work volumes exist", work_output)
    print(format_work_volumes(work_volumes))
    if arguments.no_verify:
        return 0
    # Read-only and non-destructive: --status never removes anything.
    return _verify_mount(arguments)


def _purge_work_volumes(arguments: argparse.Namespace) -> int:
    """Report the retained source copies, and delete them only when asked."""
    listed, work_volumes, work_output = _list_work_volumes(arguments)
    if not listed:
        return _report_indeterminate("which work volumes exist", work_output)
    if not work_volumes:
        print("retained work volumes (source copies): none")
        return 0
    print(format_work_volumes(work_volumes))
    if not arguments.purge_work_volumes:
        print(
            "These retain copies of source and are NOT deleted with the credential "
            "volume; pass --purge-work-volumes to delete them too."
        )
        return 0
    for name in work_volumes:
        status, output = run_capture(
            build_remove_volume_argv(remote=arguments.remote, volume=name)
        )
        if status != 0:
            print(f"ERROR: could not remove work volume {name}", file=sys.stderr)
            for line in output.strip().splitlines():
                print(f"       {line}", file=sys.stderr)
            return status or 1
        print(f"purged work volume {name}")
    return 0


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
        print(
            " ".join(
                build_work_volume_list_argv(
                    remote=arguments.remote,
                    volume=arguments.volume,
                    share_root=arguments.share_root,
                )
            )
        )
        return 0

    presence, inspect_output = _inspect_volume(arguments)
    if presence == "unknown":
        return _report_indeterminate(
            f"whether volume {arguments.volume} exists on ssh://{arguments.remote}",
            inspect_output,
        )
    if presence == "absent":
        # The credential volume may already be gone while its source copies are
        # not: that is exactly when they would otherwise be unreachable.
        print(f"volume {arguments.volume} is already absent on ssh://{arguments.remote}")
        return _purge_work_volumes(arguments)

    listed, containers, container_output = _list_containers(arguments)
    if not listed:
        return _report_indeterminate(
            f"which containers reference volume {arguments.volume}", container_output
        )
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

    status, remove_output = run_capture(remove_argv)
    if status != 0:
        print(
            f"ERROR: docker volume rm {arguments.volume} failed with exit status {status}",
            file=sys.stderr,
        )
        for line in remove_output.strip().splitlines():
            print(f"       {line}", file=sys.stderr)
        return status or 1
    print(
        f"removed volume {arguments.volume} from ssh://{arguments.remote}; "
        "the stored SMB credential is deleted with it"
    )
    print(LOCK_REMINDER)
    return _purge_work_volumes(arguments)


def _create(arguments: argparse.Namespace) -> int:
    if not arguments.dry_run:
        presence, inspect_output = _inspect_volume(arguments)
        if presence == "unknown":
            return _report_indeterminate(
                f"whether volume {arguments.volume} exists on ssh://{arguments.remote}",
                inspect_output,
            )
        if presence == "present":
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
        try:
            extra_tokens = validate_mount_options(arguments.mount_opts)
        except ValueError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        if extra_tokens:
            print(f"extra cifs options: {','.join(extra_tokens)}")
        options = build_mount_options(
            password,
            extra_options=arguments.mount_opts,
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
            rollback_status, rollback_output = run_capture(
                build_remove_volume_argv(
                    remote=arguments.remote, volume=arguments.volume
                )
            )
            if rollback_status != 0:
                print(
                    f"ERROR: rollback failed: docker volume rm {arguments.volume} exited "
                    f"{rollback_status}",
                    file=sys.stderr,
                )
                for line in rollback_output.strip().splitlines():
                    print(f"       {line}", file=sys.stderr)
                print(
                    f"       VOLUME STILL EXISTS with the stored credential; remove it "
                    f"manually with: {Path(__file__).name} --remove --volume {arguments.volume}",
                    file=sys.stderr,
                )
                return EXIT_ROLLBACK_FAILED
            print(
                f"removed volume {arguments.volume} again so an unusable credential "
                "is not left persisted on the remote host",
                file=sys.stderr,
            )
            return EXIT_MOUNT_FAILED
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
