"""Script-oriented D810 API for headless IDA sessions.

This module intentionally stays thin: it reuses :class:`d810.manager.D810State`
and the normal project/rule loading path, but avoids importing GUI modules at
module import time.
"""

from __future__ import annotations

import importlib
import pathlib

from d810.core import typing
from d810.core.logging import getLogger

logger = getLogger("D810.headless")

_state: typing.Any | None = None
_configured = False


def load_optimizer_registries(*, suppress_errors: bool = False) -> None:
    """Discover non-UI D810 modules so registry-backed optimizers are loaded."""
    d810_package = importlib.import_module("d810")
    reloadable = importlib.import_module("d810._vendor.ida_reloader")
    base_package = d810_package.__name__
    reloadable.reload_package(
        d810_package,
        skip=[
            f"{base_package}.core.registry",
            f"{base_package}._vendor",
            f"{base_package}.headless",
            f"{base_package}.ui",
        ],
        suppress_errors=suppress_errors,
    )


def _make_config(
    *,
    config_path: str | pathlib.Path | None,
    ida_user_dir: str | pathlib.Path | None,
):
    config_module = importlib.import_module("d810.core.config")
    return config_module.D810Configuration(config_path=config_path, ida_user_dir=ida_user_dir)


def _make_state():
    manager_module = importlib.import_module("d810.manager")
    return manager_module.D810State()


def _ensure_hexrays() -> bool:
    try:
        import ida_hexrays

        init = getattr(ida_hexrays, "init_hexrays_plugin", None)
        if init is not None:
            return bool(init())
    except ImportError:
        pass

    try:
        import idaapi

        return bool(idaapi.init_hexrays_plugin())
    except Exception:
        return False


def configure(
    *,
    project: str | None = None,
    config_path: str | pathlib.Path | None = None,
    config_dir: str | pathlib.Path | None = None,
    ida_user_dir: str | pathlib.Path | None = None,
) -> None:
    """Load D810 project configuration without creating the GUI.

    Args:
        project: Optional project JSON filename to select after loading.
        config_path: Optional explicit ``options.json`` path.
        config_dir: Optional directory containing ``options.json``.
        ida_user_dir: Optional IDA user directory for config/log discovery.
    """
    global _configured, _state

    if config_path is not None and config_dir is not None:
        raise ValueError("Use either config_path or config_dir, not both.")
    resolved_config_path = (
        pathlib.Path(config_dir) / "options.json" if config_dir is not None else config_path
    )

    config = _make_config(config_path=resolved_config_path, ida_user_dir=ida_user_dir)
    load_optimizer_registries()
    state = _make_state()
    state.load(gui=False, d810_config=config)

    if project is not None:
        project_names = state.project_manager.project_names()
        if project not in project_names:
            raise ValueError(
                f"Project {project!r} not found. Available projects: {', '.join(project_names)}"
            )
        state.load_project(state.project_manager.index(project))

    _state = state
    _configured = True
    logger.info("Headless configured: %s", status())


def start() -> None:
    """Install D810 Hex-Rays hooks for subsequent decompilation calls."""
    if not _configured or _state is None:
        raise RuntimeError("d810 headless API is not configured. Call configure() first.")
    if _state.manager.started:
        return
    if not _ensure_hexrays():
        raise RuntimeError("Hex-Rays decompiler is not available.")
    _state.start_d810()


def stop() -> None:
    """Remove D810 Hex-Rays hooks if they are installed."""
    if _state is None:
        return
    if _state.manager.started:
        _state.stop_d810()


def status() -> dict[str, typing.Any]:
    """Return headless configuration and hook state."""
    result: dict[str, typing.Any] = {
        "configured": _configured,
        "started": False,
        "project": None,
        "ins_rules": 0,
        "blk_rules": 0,
    }
    if _state is None:
        return result

    result["started"] = bool(_state.manager.started)
    current_project = getattr(_state, "current_project", None)
    if current_project is not None:
        result["project"] = current_project.path.name
    result["ins_rules"] = len(getattr(_state, "current_ins_rules", ()))
    result["blk_rules"] = len(getattr(_state, "current_blk_rules", ()))
    return result


__all__ = ["configure", "start", "status", "stop"]
