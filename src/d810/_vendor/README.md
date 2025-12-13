# Vendored Dependencies

This directory contains vendored (bundled) dependencies for d810 to ensure consistent behavior across different IDA Pro environments and avoid dependency conflicts.

## Why Vendor Dependencies?

IDA Pro's Python environment can be challenging:

- **Version conflicts**: IDA may bundle its own versions of packages
- **Installation issues**: Users may not have write access to IDA's Python
- **Consistency**: Different IDA versions/platforms have different packages
- **Isolation**: Avoid breaking d810 when IDA updates its Python environment

By vendoring critical dependencies, we ensure d810 works reliably regardless of the IDA Pro environment.

## Architecture

This follows pip's vendoring approach:
<https://github.com/pypa/pip/tree/main/src/pip/_vendor>

```bash
d810/_vendor/
├── __init__.py          # Package marker (no import magic needed)
├── vendor.txt           # Dependency manifest
├── README.md            # This file
└── <package>/           # Vendored package source (when needed)
    └── ...
```

**Key Design Principle**: No `sys.path` manipulation or import hooks needed!
Python's standard import system handles everything naturally.

## How It Works

### Standard Python Imports

When you vendor a package like `miasm`, Python's import system naturally resolves:

```python
# This import:
from d810._vendor.miasm.arch.x86.ira import ir_a_x86_32

# Works because:
# 1. Python finds d810/_vendor/ (it's a package)
# 2. Python finds d810/_vendor/miasm/ (it's a subdirectory)
# 3. Python imports from d810/_vendor/miasm/arch/x86/ira.py
```

**No magic, just standard Python imports!**

### In d810 Code

```python
# Old (direct dependency):
from miasm.arch.x86.ira import ir_a_x86_32

# New (vendored):
from d810._vendor.miasm.arch.x86.ira import ir_a_x86_32
```

## When to Vendor a Dependency

Vendor a dependency when:

- ✅ It causes conflicts with IDA Pro's bundled packages
- ✅ We need a specific version not available in IDA
- ✅ We need to apply custom patches for IDA compatibility
- ✅ It's critical for d810's core functionality
- ✅ It's not available in PyPI or installation is problematic

**Don't vendor** when:

- ❌ Package works fine as a regular dependency
- ❌ Package is large and rarely causes issues
- ❌ We don't need a specific version

## Current Status

**Currently vendored**:

1. **`ida-reloader`** (v0.1.0+d810) - Hot-reload infrastructure for IDA Pro plugins
   - Source: <https://github.com/mahmoudimus/ida-reloader>
   - Provides: `Reloader`, `DependencyGraph`, `_Scanner`, `reload_package()`
   - Reason: Core infrastructure for plugin hot-reloading, tightly integrated with d810
   - Location: `src/d810/_vendor/ida_reloader/`
   - Usage: `from d810._vendor.ida_reloader import Reloader`

2. **`typing_extensions`** (v4.15.0) - Backport of latest typing features
   - Source: <https://github.com/python/typing_extensions>
   - Provides: `Protocol`, `TypedDict`, `Literal`, `Final`, `override`, `Self`, etc.
   - Reason: Ensure consistent typing support across Python 3.10-3.13
   - Location: `src/d810/_vendor/typing_extensions.py`
   - Usage: `from d810._vendor.typing_extensions import Protocol, override`
   - Note: Accessed via `d810.typing` module for cross-version compatibility

3. **`clang`** (v19.1.0+d810) - Python bindings for the Clang indexing library
   - Source: <https://github.com/llvm/llvm-project/tree/main/clang/bindings/python>
   - Provides: `cindex` module (`Index`, `TranslationUnit`, `Cursor`, etc.)
   - Reason: Required for C/C++ AST parsing in test infrastructure
   - Location: `src/d810/_vendor/clang/`
   - Usage: `from d810._vendor.clang import cindex`
   - License: Apache-2.0 WITH LLVM-exception
   - Note: Manually vendored (not available as standalone PyPI package)

**Candidates for future vendoring**:

- `miasm2`: If we need custom patches for IDA compatibility
- `z3-solver`: If bundling is needed for binary distributions

## Vendoring a New Package

### Method 1: Automatic Vendoring (Recommended)

Use the `vendoring` tool for packages available on PyPI:

1. **Evaluate Need**
   - Does this package cause conflicts in IDA Pro?
   - Do we need a specific version or custom patches?
   - Is it available on PyPI?
2. **Install vendoring tool** (one-time setup)

    ```bash
    pip install vendoring
    ```

3. **Add package to vendor.txt**

    ```bash
    # Add the package and version
    echo "package==1.2.3" >> src/d810/_vendor/vendor.txt
    echo "    # Reason: Brief explanation" >> src/d810/_vendor/vendor.txt
    ```

4. **Run vendoring sync**

    ```bash
    # From project root
    python -m vendoring sync
    ```

    This automatically:

    - Downloads the package from PyPI
    - Extracts it to `src/d810/_vendor/`
    - Downloads LICENSE files
    - Applies any patches from `tools/vendoring/patches/`
    - Generates type stubs

5. **Update imports in d810 code**

    ```bash
    # Find all imports
    grep -r "from package import" src/d810/
    grep -r "import package" src/d810/

    # Replace with vendored imports
    # from package import X → from d810._vendor.package import X
    ```

6. **Test**

    ```bash
    # Run tests
    pytest tests/

    # Test in IDA Pro
    python -c "import idapro; from d810._vendor.package import X; print('✓ Works!')"
    ```

7. **Commit**

    ```bash
    git add src/d810/_vendor/
    git commit -m "vendor: Add package==1.2.3"
    ```

### Method 2: Manual Vendoring

Use manual vendoring when:

- Package is not on PyPI
- Package needs significant modifications
- You want fine-grained control

1. **Download Package Source**

    ```bash
    # From GitHub release
    wget https://github.com/org/package/archive/v1.2.3.tar.gz
    tar xzf v1.2.3.tar.gz
    cd package-1.2.3

    # Or clone from git
    git clone https://github.com/org/package /tmp/package
    cd /tmp/package
    git checkout v1.2.3
    ```

2. **Copy to Vendor Directory**

    ```bash
    # Copy package source (the actual Python package, not the repo)
    # If the package is in src/package/:
    cp -r /tmp/package/src/package /path/to/d810-ng/src/d810/_vendor/package

    # If the package IS the root:
    cp -r /tmp/package /path/to/d810-ng/src/d810/_vendor/package

    # Clean up unnecessary files
    cd /path/to/d810-ng/src/d810/_vendor/package
    rm -rf tests/ testing/ .git/ .github/ __pycache__/ *.pyc
    ```

3. **Document in vendor.txt**

    ```bash
    # Add to vendor.txt (even for manual vendoring, for documentation)
    echo "" >> src/d810/_vendor/vendor.txt
    echo "# package - Brief description" >> src/d810/_vendor/vendor.txt
    echo "# Source: https://github.com/org/package" >> src/d810/_vendor/vendor.txt
    echo "# NOTE: Manually vendored (not on PyPI / needs custom patches)" >> src/d810/_vendor/vendor.txt
    echo "package==1.2.3+d810" >> src/d810/_vendor/vendor.txt
    ```

4. **Create Patches (if needed)**

    If you need to modify imports within the vendored package:

    ```bash
    # Create a patch
    cat > tools/vendoring/patches/package.patch << 'EOF'
    --- a/src/d810/_vendor/package/module.py
    +++ b/src/d810/_vendor/package/module.py
    @@ -1,4 +1,4 @@
    -from dependency import something
    +from d810._vendor.dependency import something
    EOF

    # Apply it
    cd src/d810/_vendor/package
    patch -p4 < ../../../tools/vendoring/patches/package.patch
    ```

5. **Update imports & test** (same as automatic method)

6. **Document in README**

    Add to the "Currently vendored" section:

    - Package name and version
    - Source URL
    - Why it was vendored
    - What it provides
    - Any special notes (manual vendoring, patches, etc.)

## Updating Vendored Packages

### Automatic Updates (via vendoring tool)

```bash
# Update all vendored packages to versions specified in vendor.txt
python -m vendoring sync

# Or update a specific package
python -m vendoring update package-name
```

### Manual Updates

1. Download new version (same as initial manual vendoring)
2. Remove old version: `rm -rf src/d810/_vendor/package/`
3. Copy new version (follow manual vendoring steps)
4. Update version in `vendor.txt`
5. Re-apply any patches if needed
6. Test thoroughly

## Configuration

### pyproject.toml

```toml
[tool.vendoring]
destination = "src/d810/_vendor/"
requirements = "src/d810/_vendor/vendor.txt"
namespace = "d810._vendor"
protected-files = ["__init__.py", "README.md", "vendor.txt"]
patches-dir = "tools/vendoring/patches"

[tool.vendoring.transformations]
drop = [
    # Exclude unnecessary files to reduce size
    "*.c",           # C extension source (we don't compile vendored packages)
    "*.so",          # Compiled extensions
    "test/",         # Tests
    "tests/",
    "example/",
    "examples/",
    "doc/",
    "docs/",
    ".git/",
    ".github/",
    "__pycache__/",
    "*.pyc",
]

substitute = [
    # Rewrite imports if vendored packages import each other
    # Example: {match='from dependency import', replace='from d810._vendor.dependency import'}
]

# License fallback URLs for packages that don't bundle licenses in their distributions
# IMPORTANT: Use underscores (_) not hyphens (-) in package names!
# The vendoring tool normalizes all package names to underscores internally.
[tool.vendoring.license.fallback-urls]
ida_reloader = "https://raw.githubusercontent.com/mahmoudimus/ida-reloader/main/LICENSE"
typing_extensions = "https://raw.githubusercontent.com/python/typing_extensions/main/LICENSE"

[tool.pytest.ini_options]
# Exclude vendored packages from testing
addopts = ["--ignore=src/d810/_vendor"]

[tool.coverage.run]
# Exclude vendored packages from coverage
omit = ["*/d810/_vendor/*"]
```

### .gitignore

```gitignore
# Vendored package caches
src/d810/_vendor/**/__pycache__/
src/d810/_vendor/**/*.pyc
src/d810/_vendor/**/*.pyo

# Don't ignore vendored source itself
# (vendored packages ARE checked into git)
```

## Maintenance

### Updating a Vendored Package

1. Update version in `vendor.txt`
2. Remove old package: `rm -rf src/d810/_vendor/package`
3. Follow "Vendoring a New Package" steps above
4. Re-apply patches from `tools/vendoring/patches/`
5. Test thoroughly
6. Commit with descriptive message

### Removing a Vendored Package

1. Remove from `src/d810/_vendor/package/`
2. Remove from `vendor.txt`
3. Remove patches from `tools/vendoring/patches/`
4. Update all imports in d810 code
5. Update this README
6. Test thoroughly

## Best Practices

1. **Version pinning**: Always pin exact versions in `vendor.txt`
2. **Minimal vendoring**: Only vendor what's absolutely necessary
3. **Document patches**: Every patch needs a comment explaining why
4. **Test in IDA**: Always test vendored packages in actual IDA Pro
5. **Track upstream**: Monitor vendored packages for security updates
6. **Clean commits**: One package per commit for easy rollback

## Troubleshooting

### Import Errors

```python
ModuleNotFoundError: No module named 'd810._vendor.package'
```

**Fix**: Verify package is in `src/d810/_vendor/package/` with `__init__.py`

### Circular Imports

```python
ImportError: cannot import name 'X' from partially initialized module
```

**Fix**: Check for circular imports in vendored packages. May need patching.

### Version Conflicts

```bash
Package 'X' requires 'Y>=2.0' but vendored version is 1.5
```

**Fix**: Update vendored package or patch to remove version check if safe.

### License Fetch Fails with "No hardcoded license URL"

```python
ValueError: No hardcoded license URL for my_package
```

**Fix**: The vendoring tool normalizes package names to use underscores (`_`) instead of hyphens (`-`).
In `pyproject.toml`, use `my_package` not `my-package` in `[tool.vendoring.license.fallback-urls]`.

## References

- [pip's vendoring documentation](https://github.com/pypa/pip/tree/main/src/pip/_vendor)
- [vendoring tool](https://pypi.org/project/vendoring/)
- [Why vendor dependencies?](https://pythonspeed.com/articles/vendoring/)

## Questions?

- Check pip's implementation for reference: <https://github.com/pypa/pip/tree/main/src/pip/_vendor>
- The key insight: **No import magic needed!** Just use standard Python imports with the `d810._vendor` namespace.
