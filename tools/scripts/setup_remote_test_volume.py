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

Examples::

    python3 tools/scripts/setup_remote_test_volume.py --dry-run
    python3 tools/scripts/setup_remote_test_volume.py --remote remote-engine.example
"""

from __future__ import annotations

import argparse
import getpass
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
        help="print the redacted docker argv instead of running it",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    password = ""
    try:
        try:
            password = getpass.getpass(
                f"SMB password for {arguments.user}@{share_host(arguments.share)}: "
            )
        except (EOFError, KeyboardInterrupt):
            print("ERROR: no SMB password was entered", file=sys.stderr)
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
        if arguments.dry_run:
            print(printable)
            return 0
        print(printable)
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
        return 0
    finally:
        password = ""
        del password


if __name__ == "__main__":
    raise SystemExit(main())
