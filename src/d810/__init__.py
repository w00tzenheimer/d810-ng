__version__ = "0.6.6"

try:
    from d810.speedups.bootstrap import ensure_speedups_on_path

    ensure_speedups_on_path()
except Exception:
    # Keep package import robust even if environment setup is incomplete.
    pass


def get_headless_api():
    """Return the script-oriented headless API module."""
    import importlib

    return importlib.import_module("d810.headless")
