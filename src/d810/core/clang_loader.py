"""Shared libclang discovery/loading helpers.

Centralizes libclang lookup so runtime code and tests use the same logic.
"""

from __future__ import annotations

import pathlib
import platform
from d810.core import typing


def _platform_lib_name(system_name: str | None = None) -> str:
    system = system_name or platform.system()
    return {
        "Linux": "libclang.so",
        "Darwin": "libclang.dylib",
        "Windows": "libclang.dll",
    }.get(system, "libclang.so")


def discover_libclang_candidates(
    *,
    ida_directory: str | pathlib.Path | None = None,
    project_root: str | pathlib.Path | None = None,
    system_name: str | None = None,
) -> list[pathlib.Path]:
    """Return ordered candidate paths for libclang."""
    system = system_name or platform.system()
    lib_name = _platform_lib_name(system)
    candidates: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()

    def add(path: pathlib.Path) -> None:
        p = path.expanduser()
        if p in seen:
            return
        seen.add(p)
        candidates.append(p)

    if ida_directory:
        ida_dir = pathlib.Path(ida_directory)
        add(ida_dir / lib_name)
        add(ida_dir / "Contents" / "MacOS" / lib_name)

    # Useful in headless test/runtime environments.
    env_ida_dir = __import__("os").environ.get("IDA_INSTALL_DIR")
    if env_ida_dir:
        env_dir = pathlib.Path(env_ida_dir)
        add(env_dir / lib_name)
        add(env_dir / "Contents" / "MacOS" / lib_name)

    # Project-local development copy.
    if project_root:
        add(pathlib.Path(project_root) / lib_name)

    # macOS app bundle fallbacks.
    if system == "Darwin":
        add(pathlib.Path("/Applications/IDA Professional 9.2.app/Contents/MacOS") / lib_name)
        add(pathlib.Path("/Applications/IDA Professional 9.1.app/Contents/MacOS") / lib_name)
        app_root = pathlib.Path("/Applications")
        if app_root.exists():
            for base in sorted(app_root.glob("IDA Professional *.app/Contents/MacOS")):
                add(base / lib_name)

    # Explicit override path.
    env_libclang = __import__("os").environ.get("D810_LIBCLANG_PATH")
    if env_libclang:
        add(pathlib.Path(env_libclang))

    return candidates


def load_clang_index(
    *,
    ida_directory: str | pathlib.Path | None = None,
    project_root: str | pathlib.Path | None = None,
    system_name: str | None = None,
    allow_default_loader: bool = False,
) -> tuple[typing.Any | None, pathlib.Path | None, list[pathlib.Path]]:
    """Load clang Index from discovered libclang path.

    Returns:
        (index_or_none, loaded_path_or_none, tried_paths)
    """
    try:
        from d810._vendor.clang.cindex import Config, Index
    except ImportError:
        return None, None, []

    candidates = discover_libclang_candidates(
        ida_directory=ida_directory,
        project_root=project_root,
        system_name=system_name,
    )

    for path in candidates:
        if not path.exists():
            continue

        # set_library_file can fail if libclang is already loaded; in that case,
        # try Index.create() anyway against the currently loaded library.
        try:
            Config.set_library_file(str(path.resolve()))
        except Exception:
            pass

        try:
            return Index.create(), path, candidates
        except Exception:
            continue

    if allow_default_loader:
        # Optional last resort for environments that intentionally do not use
        # IDA's packaged libclang.
        try:
            return Index.create(), None, candidates
        except Exception:
            pass

    return None, None, candidates
