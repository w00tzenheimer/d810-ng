"""
IDA Reloader - Hot-reload infrastructure for IDA plugins.

This package provides hot-reload functionality with dependency graph analysis
and cycle detection for IDA Pro plugins.
"""

from . import ida_reloader as _ida_reloader

__version__ = _ida_reloader.__version__
DependencyGraph = _ida_reloader.DependencyGraph
Reloader = _ida_reloader.Reloader
Scanner = _ida_reloader.Scanner
reload_package = _ida_reloader.reload_package
Plugin = _ida_reloader.Plugin
LateInitPlugin = _ida_reloader.LateInitPlugin
ReloadablePluginBase = _ida_reloader.ReloadablePluginBase

__all__ = [
    "__version__",
    "DependencyGraph",
    "Reloader",
    "Scanner",
    "reload_package",
    "Plugin",
    "LateInitPlugin",
    "ReloadablePluginBase",
]
