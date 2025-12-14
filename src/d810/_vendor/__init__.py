"""
d810._vendor is for vendoring dependencies of d810 to prevent dependency
conflicts with IDA Pro's Python environment.

Vendored dependencies are isolated in this namespace to avoid conflicts with:
- IDA Pro's bundled packages
- User-installed packages in IDA's Python environment
- System packages

This follows the same pattern as pip's vendoring:
https://github.com/pypa/pip/tree/main/src/pip/_vendor

Usage:
    # Instead of:
    from miasm.arch.x86.ira import ir_a_x86_32

    # Use:
    from d810._vendor.miasm.arch.x86.ira import ir_a_x86_32

Vendored packages are checked into git as full source directories.
See vendor.txt for the list of vendored dependencies.
"""

# NOTE: Unlike pip, we don't need debundling support since d810 is not
# packaged by downstream redistributors. This keeps the implementation simple.

__all__ = []  # No exports needed - vendored packages are imported directly
