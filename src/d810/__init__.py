__version__ = "0.6.6"

try:
    from d810.speedups.bootstrap import ensure_speedups_on_path

    ensure_speedups_on_path()
except Exception:
    # Keep package import robust even if environment setup is incomplete.
    pass
