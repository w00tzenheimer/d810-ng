"""The published d810-cobra identity, read from its single source of truth.

``docker/cobra-bake/published_identity`` is the only place the published wheel
hashes, release version and commits are written down. The image bake reads it
from bash, the Docker test runner reads it from bash, and the tests of both
read it from here -- so a wheel rotation is one edit in one file, or it is a
test failure.

>>> identity = published_identity()
>>> identity.version
'0.1.5'
>>> identity.wheels["aarch64"].sha256[:12]
'2c85ffe14a1f'
"""

from __future__ import annotations

from pathlib import Path

from d810.core.typing import Mapping, NamedTuple

__all__ = [
    "PUBLISHED_IDENTITY_FILE",
    "PublishedIdentity",
    "PublishedWheel",
    "published_identity",
]

PUBLISHED_IDENTITY_FILE = (
    Path(__file__).resolve().parents[1]
    / "docker"
    / "cobra-bake"
    / "published_identity"
)

_COLUMNS = 7


class PublishedWheel(NamedTuple):
    """One architecture's published artifact."""

    arch: str
    sha256: str
    filename: str


class PublishedIdentity(NamedTuple):
    """The release every published wheel in the file belongs to."""

    version: str
    tag_commit: str
    core_commit: str
    parent_commit: str
    wheels: Mapping[str, PublishedWheel]


def published_identity(path: Path | None = None) -> PublishedIdentity:
    """Parse the identity file, refusing anything it cannot fully verify.

    Malformed input raises rather than yielding a partial table: a caller that
    silently accepted half of it would compare an artifact against a value
    nobody wrote.
    """
    source = PUBLISHED_IDENTITY_FILE if path is None else path
    wheels: dict[str, PublishedWheel] = {}
    release: tuple[str, str, str] | None = None
    for number, line in enumerate(
        source.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) != _COLUMNS:
            raise ValueError(f"{source}:{number}: expected {_COLUMNS} columns")
        arch, sha256, version, tag, core, parent, filename = fields
        if len(sha256) != 64 or sha256.strip("0123456789abcdef"):
            raise ValueError(f"{source}:{number}: {sha256} is not a sha256")
        for commit in (tag, core, parent):
            if len(commit) != 40 or commit.strip("0123456789abcdef"):
                raise ValueError(f"{source}:{number}: {commit} is not a commit")
        if arch in wheels:
            raise ValueError(f"{source}:{number}: duplicate architecture {arch}")
        if release is not None and release != (version, tag, core):
            raise ValueError(f"{source}:{number}: describes a second release")
        release = (version, tag, core)
        parent_commit = parent
        wheels[arch] = PublishedWheel(arch=arch, sha256=sha256, filename=filename)
    if release is None:
        raise ValueError(f"{source}: names no published wheel")
    return PublishedIdentity(
        version=release[0],
        tag_commit=release[1],
        core_commit=release[2],
        parent_commit=parent_commit,
        wheels=wheels,
    )
