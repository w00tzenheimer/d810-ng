#: Pre-release for the 1.0.0 cutover, where this line replaces ``main``.
#:
#: Spelled the PEP 440 canonical way rather than "1.0.0-beta": both are valid
#: and equal, but setuptools normalizes "1.0.0-beta" to "1.0.0b0", so
#: ``d810.__version__`` and ``pip show`` would report different strings for one
#: release.
#:
#: A pre-release sorts BEFORE the final (``1.0.0b2 < 1.0.0``), and pip ignores
#: pre-releases unless a specifier opts in. Anything depending on the new
#: extension seam must therefore pin ``>=1.0.0b2``, not ``>=1.0.0`` -- the
#: latter rejects every beta, which reads as "not released yet" rather than as
#: a version mismatch.
__version__ = "1.0.0b2"

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
