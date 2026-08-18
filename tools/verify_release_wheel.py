"""Verify that a built d810 wheel has usable backends and native speedups."""

from __future__ import annotations

from collections.abc import Callable, Sequence
import sys

from d810.backends import registry
from d810.core.plugins import BackendInfo
from d810.core.plugins import format_report, has_defects
from d810.core.typing import TextIO
from d810.speedups.install import NativeSpeedupsProbe, inspect_native_extensions


def verify_release_wheel(
    *,
    backend_probe: Callable[[], Sequence[BackendInfo]] | None = None,
    native_probe: Callable[[], NativeSpeedupsProbe] | None = None,
    output: TextIO | None = None,
) -> int:
    """Probe the installed wheel and return a shell-friendly status code.

    The probe callables are injectable only so unit tests can exercise the
    decision and reporting behavior without requiring compiled extensions in
    the source checkout. The defaults are the actual installed-wheel probes.
    """
    stream = sys.stdout if output is None else output
    infos = (registry().probe_all() if backend_probe is None else backend_probe())
    native = (
        inspect_native_extensions()
        if native_probe is None
        else native_probe()
    )

    print("Backend registry:", file=stream)
    print(format_report(infos), file=stream)
    print(
        f"Native extensions: {'OK' if native.ok else 'FAILED'}",
        file=stream,
    )
    print(native.detail, file=stream)
    return int(has_defects(infos) or not native.ok)


def main() -> int:
    """Run the installed-wheel verification command."""
    return verify_release_wheel()


if __name__ == "__main__":
    raise SystemExit(main())
