"""Optional Cython extension builder for D810.

By default, D810 installs as a pure Python package.
To build with Cython speedups:

    D810_BUILD_SPEEDUPS=1 pip install -e .[speedups]

The IDA SDK will be auto-downloaded from GitHub if not found.
Set IDA_SDK env var to use a custom location.

This setup.py only handles ext_modules; all other config is in pyproject.toml.
"""

import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from setuptools import setup

BUILD_SPEEDUPS = os.environ.get("D810_BUILD_SPEEDUPS", "0") == "1"

# Default SDK location (in build directory)
DEFAULT_SDK_DIR = pathlib.Path(__file__).parent / ".ida-sdk"
IDA_SDK_REPO = "https://github.com/HexRaysSA/ida-sdk.git"
IDA_SDK_BRANCH = "main"

# Platform detection
OSTYPE = platform.system()
ARCH = (platform.processor() or platform.machine()).lower()
x64 = platform.architecture()[0] == "64bit"
DEBUG = os.environ.get("DEBUG") == "1"

# Determine library variant
if ARCH in ("ppc64le", "aarch64"):
    LIBRARY = ARCH
elif ARCH in ("arm", "arm64"):
    LIBRARY = "arm64"
else:
    LIBRARY = "amd64" if x64 else "intel32"


def _sdk_has_includes(path: pathlib.Path) -> bool:
    """Check if an SDK path has the include directory (either layout)."""
    return (path / "src" / "include").exists() or (path / "include").exists()


def _sdk_include_dir(sdk_path: pathlib.Path) -> pathlib.Path:
    """Return the include directory for the SDK, handling both layouts.

    GitHub SDK clone: sdk/src/include/
    User IDA SDK:     sdk/include/
    """
    if (sdk_path / "src" / "include").exists():
        return sdk_path / "src" / "include"
    return sdk_path / "include"


def _sdk_lib_dir(sdk_path: pathlib.Path, *sub: str) -> pathlib.Path:
    """Return a library directory for the SDK, handling both layouts."""
    if (sdk_path / "src" / "lib").exists():
        return (
            sdk_path / "src" / "lib" / pathlib.Path(*sub)
            if sub
            else sdk_path / "src" / "lib"
        )
    return sdk_path / "lib" / pathlib.Path(*sub) if sub else sdk_path / "lib"


def _linux_sdk_lib_subdir(library: str = LIBRARY, is_64bit: bool = x64) -> str:
    """Return the IDA SDK Linux library subdirectory for this architecture."""
    if library in ("aarch64", "arm64"):
        return "arm64_linux_64"
    if is_64bit:
        return "x64_linux_64"
    return "x86_linux_32"


def _select_linux_sdk_lib_dir(sdk_path: pathlib.Path) -> pathlib.Path:
    """Return the best Linux SDK library directory, with legacy SDK fallback."""
    current = _sdk_lib_dir(sdk_path, _linux_sdk_lib_subdir())
    if current.exists():
        return current

    legacy = _sdk_lib_dir(sdk_path, "x64_linux_gcc_64")
    if legacy.exists():
        return legacy

    return current


def _windows_sdk_lib_subdir(
    sdk_version: int,
    library: str = LIBRARY,
    is_64bit: bool = x64,
) -> str:
    """Return the Windows SDK library subdirectory for an IDA SDK version.

    IDA 9.4 introduced native Windows ARM64 support and renamed the 64-bit
    import-library directories.  Older SDKs use ``x64_win_vc_64``; IDA 9.4+
    uses ``x64_win_64`` or ``arm64_win_64`` according to the build ABI.
    """
    normalized_library = str(library).lower()
    is_arm64 = normalized_library in {"arm64", "aarch64"}

    if is_arm64 and int(sdk_version) < 940:
        raise ValueError("ARM64 Windows SDK libraries require IDA 9.4 or newer")

    if int(sdk_version) >= 940:
        if is_arm64:
            return "arm64_win_64"
        return "x64_win_64" if is_64bit else "x64_win_32"

    return "x64_win_vc_64" if is_64bit else "x64_win_32"


def _ida_runtime_lib_dir() -> pathlib.Path | None:
    """Return the live IDA runtime library directory when available."""
    install_dir = os.environ.get("IDA_INSTALL_DIR") or os.environ.get("IDA_PREFIX")
    if not install_dir:
        return None

    runtime_dir = pathlib.Path(install_dir)
    if (runtime_dir / "libida.so").exists():
        return runtime_dir
    return None


def get_ida_sdk_version(sdk_path: pathlib.Path) -> int:
    """Read the IDA SDK version number from pro.h.

    Returns the SDK version (e.g. 920 for IDA 9.2), or 0 if not found.
    """
    pro_h = _sdk_include_dir(sdk_path) / "pro.h"
    if pro_h.exists():
        with pro_h.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("#define IDA_SDK_VERSION"):
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2].isdigit():
                        return int(parts[2])
    return 0


def ensure_ida_sdk(sdk_path: pathlib.Path) -> pathlib.Path:
    """Ensure IDA SDK is available, downloading if necessary."""
    # If SDK exists, use it (GitHub SDK has include under src/,
    # user-provided SDK may have include/ at root)
    if sdk_path.exists() and _sdk_has_includes(sdk_path):
        print(f"Using IDA SDK at: {sdk_path}", file=sys.stderr)
        return sdk_path

    # Check cached SDK
    if DEFAULT_SDK_DIR.exists() and _sdk_has_includes(DEFAULT_SDK_DIR):
        print(f"Using cached IDA SDK at: {DEFAULT_SDK_DIR}", file=sys.stderr)
        return DEFAULT_SDK_DIR

    # Download SDK from GitHub
    print(f"IDA SDK not found. Downloading from {IDA_SDK_REPO}...", file=sys.stderr)

    # Clean up partial/corrupt SDK directory (exists but missing includes)
    if DEFAULT_SDK_DIR.exists() and not _sdk_has_includes(DEFAULT_SDK_DIR):
        print(f"Removing partial SDK directory: {DEFAULT_SDK_DIR}", file=sys.stderr)
        shutil.rmtree(DEFAULT_SDK_DIR)

    # Try git clone first (faster, gets only latest)
    if shutil.which("git"):
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "--branch",
                    IDA_SDK_BRANCH,
                    IDA_SDK_REPO,
                    str(DEFAULT_SDK_DIR),
                ],
                check=True,
                capture_output=True,
            )
            print(f"IDA SDK downloaded to: {DEFAULT_SDK_DIR}", file=sys.stderr)
            return DEFAULT_SDK_DIR
        except subprocess.CalledProcessError as e:
            print(f"git clone failed: {e.stderr.decode()}", file=sys.stderr)
            # Clean up partial clone before tarball fallback
            if DEFAULT_SDK_DIR.exists() and not _sdk_has_includes(DEFAULT_SDK_DIR):
                shutil.rmtree(DEFAULT_SDK_DIR)

    # Fallback: download tarball
    #
    # The handle is closed before the path is written to or removed. Windows
    # refuses to reopen or delete a file while another handle is open, so
    # holding a NamedTemporaryFile open across the download and extraction
    # made the cleanup fail with PermissionError (WinError 32) every time.
    tmp_path = None
    try:
        tarball_url = f"https://github.com/HexRaysSA/ida-sdk/archive/refs/heads/{IDA_SDK_BRANCH}.tar.gz"
        print(f"Downloading {tarball_url}...", file=sys.stderr)

        handle, tmp_path = tempfile.mkstemp(suffix=".tar.gz")
        os.close(handle)

        urllib.request.urlretrieve(tarball_url, tmp_path)

        with tarfile.open(tmp_path, "r:gz") as tar:
            with tempfile.TemporaryDirectory() as tmpdir:
                try:
                    tar.extractall(tmpdir, filter="data")
                except TypeError:
                    tar.extractall(tmpdir)
                extracted = next(pathlib.Path(tmpdir).iterdir())
                shutil.move(str(extracted), str(DEFAULT_SDK_DIR))

        print(f"IDA SDK downloaded to: {DEFAULT_SDK_DIR}", file=sys.stderr)
        return DEFAULT_SDK_DIR

    except Exception as e:
        raise RuntimeError(
            f"Failed to download IDA SDK: {e}\n"
            f"Please manually clone: git clone {IDA_SDK_REPO} {DEFAULT_SDK_DIR}\n"
            f"Or set IDA_SDK environment variable to your SDK location."
        )
    finally:
        # Also runs when extraction fails, where the original leaked the file.
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def get_compile_args(sdk_version: int = 0):
    """Return platform-specific compilation arguments."""
    if OSTYPE == "Windows":
        standard_args = ["/std:c++17"] if int(sdk_version) >= 940 else []
        return ["/TP", "/EHa"] + standard_args + (["/Z7", "/Od"] if DEBUG else [])
    elif OSTYPE == "Linux":
        base = ["-Wno-stringop-truncation", "-Wno-catch-value", "-Wno-unused-variable"]
        return base + (["-g", "-O0"] if DEBUG else [])
    elif OSTYPE == "Darwin":
        warnings = [
            "-Wno-unused-variable",
            "-Wno-nullability-completeness",
            "-Wno-sign-compare",
            "-Wno-varargs",
            "-Wno-c99-extensions",
        ]
        base = ["-mmacosx-version-min=10.9"] + warnings
        return base + (["-g", "-O0", "-fno-omit-frame-pointer"] if DEBUG else [])
    return []


def get_link_args():
    """Return platform-specific linker arguments."""
    if OSTYPE == "Darwin":
        return ["-Wl,-headerpad_max_install_names,-rpath,@loader_path/lib"]
    elif OSTYPE == "Linux":
        return ["-Wl,-rpath,$ORIGIN/lib"]
    return []


def get_ext_modules():
    """Build Cython extensions if D810_BUILD_SPEEDUPS=1, else return empty list."""
    # Re-check at call time (not just module-load time) so subprocess
    # invocations by pip/setuptools always see the current env.
    want_speedups = os.environ.get("D810_BUILD_SPEEDUPS", "0") == "1"
    if not want_speedups:
        return []

    try:
        from Cython.Build import cythonize
        from setuptools import Extension
    except ImportError:
        raise ImportError(
            "Cython is required to build speedups. "
            "Install with: pip install 'd810[speedups]'"
        )

    # Get IDA SDK (download if needed)
    sdk_env = os.environ.get("IDA_SDK")
    sdk_path = pathlib.Path(sdk_env) if sdk_env else DEFAULT_SDK_DIR
    IDA_SDK = ensure_ida_sdk(sdk_path)

    sdk_version = get_ida_sdk_version(IDA_SDK)
    print(f"IDA SDK version: {sdk_version}", file=sys.stderr)

    include_dirs = [
        str(_sdk_include_dir(IDA_SDK)),
        str(pathlib.Path(__file__).parent / "src" / "include"),
    ]
    library_dirs = [str(_sdk_lib_dir(IDA_SDK))]

    # Platform-specific library paths
    runtime_library_dirs = []
    if OSTYPE == "Windows":
        library_dirs.append(
            str(_sdk_lib_dir(IDA_SDK, _windows_sdk_lib_subdir(sdk_version)))
        )

        # No Qt. The speedups define neither __QT__ nor QT_NAMESPACE and add no
        # Qt include directory, so nothing here ever references a Qt symbol.
        # Verified on Windows: dropping Qt6Core/Gui/Widgets links all modules
        # with zero unresolved externals, and the resulting .pyd import tables
        # are identical to the Qt-linked build (python313, KERNEL32,
        # VCRUNTIME140, api-ms-win-crt-runtime only).
        #
        # This also fixes SDK 9.4, which no longer ships lib/x64_win_qt: naming
        # those libraries made the link fail on a .lib that no longer exists.
        libraries = ["ida", "idalib"]
    elif OSTYPE == "Darwin":
        subdir = "arm64_mac_clang_64" if LIBRARY == "arm64" else "x64_mac_clang_64"
        library_dirs.append(str(_sdk_lib_dir(IDA_SDK, subdir)))
        libraries = []
    else:  # Linux
        runtime_lib_dir = _ida_runtime_lib_dir()
        if runtime_lib_dir is not None:
            library_dirs.append(str(runtime_lib_dir))
            runtime_library_dirs.append(str(runtime_lib_dir))

        linux_lib_dir = str(_select_linux_sdk_lib_dir(IDA_SDK))
        library_dirs.append(linux_lib_dir)
        libraries = ["ida"]
        runtime_library_dirs.append(linux_lib_dir)

    macros = [("__EA64__", "1")] if x64 else []
    if DEBUG:
        macros.extend([("CYTHON_TRACE", "1"), ("CYTHON_CLINE_IN_TRACEBACK", "1")])

    return cythonize(
        Extension(
            "*",
            ["src/d810/speedups/**/*.pyx"],
            language="c++",
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            runtime_library_dirs=runtime_library_dirs,
            extra_compile_args=get_compile_args(sdk_version),
            extra_link_args=get_link_args(),
            define_macros=macros,
        ),
        compiler_directives={
            "language_level": "3",
            "binding": True,
            "embedsignature": True,
            "boundscheck": False,
            "wraparound": False,
            "profile": DEBUG,
            "linetrace": DEBUG,
        },
        annotate=DEBUG,
    )


def _first_existing(root, relatives):
    """Return the first relative path under *root* that exists, else None."""
    for rel in relatives:
        candidate = root / rel
        if candidate.exists():
            return candidate
    return None


def get_cobra_ext_modules():
    """Build the CoBRA solver binding if D810_BUILD_COBRA=1, else nothing.

    Deliberately a SEPARATE Extension from the speedups above, for two reasons
    that are not stylistic:

    * The speedups glob carries IDA-SDK include/library dirs.  A CoBRA source
      dropped under ``src/d810/speedups`` would inherit them, and would also
      make CoBRA a hard requirement for everyone building speedups.
    * The IDA SDK does not compile as C++23 (``pro.h`` uses ``std::is_pod``,
      removed in C++23) while CoBRA requires it (``Result.h`` uses
      ``std::expected``).  The two can never share compiler flags, let alone a
      translation unit.
    """
    if os.environ.get("D810_BUILD_COBRA", "0") != "1":
        return []

    try:
        from Cython.Build import cythonize
        from setuptools import Extension
    except ImportError:
        raise ImportError("Cython is required to build the CoBRA binding")

    cobra_root = os.environ.get("COBRA_ROOT")
    if not cobra_root:
        raise RuntimeError(
            "D810_BUILD_COBRA=1 requires COBRA_ROOT to point at a CoBRA build "
            "tree (CoBRA exports no CMake package to discover)"
        )
    root = pathlib.Path(cobra_root)

    here = pathlib.Path(__file__).parent / "src" / "d810" / "backends" / "cobra"

    # TWO accepted layouts. The flat one exists so a released/CI static-lib
    # bundle can be consumed directly -- requiring callers to reshape a
    # download into a fake build tree is pure friction, and reshaping inside CI
    # just relocates it.
    #
    #   FLAT (release / CI artifact):  <root>/lib/*.{a,lib}   <root>/include/
    #   BUILD TREE (local checkout):   <root>/build/lib/core/
    #                                  <root>/build-deps/install/{lib*,include}/
    flat_lib = root / "lib"
    flat_inc = root / "include"
    is_flat = flat_lib.is_dir() and any(flat_lib.glob("*cobra-core*"))

    if is_flat:
        include_dirs = [str(here), str(flat_inc)]
        library_dirs = [str(flat_lib)]
    else:
        # Pick ONE dependency prefix and one core build; globbing several and
        # merging them silently mixes incompatible trees.
        deps_prefix = _first_existing(
            root, ("build-deps/install", "build-deps-nollvm/install")
        )
        core_dir = _first_existing(root, ("build/lib/core", "build-nollvm/lib/core"))
        if deps_prefix is None or core_dir is None:
            raise RuntimeError(
                f"COBRA_ROOT={root} does not look built. Accepted layouts:\n"
                f"  flat:       {root}/lib/*cobra-core* + {root}/include/\n"
                f"  build tree: {root}/build/lib/core + {root}/build-deps/install\n"
                "(see CoBRA BUILD.md, or use a cobra-core-<platform> bundle)"
            )
        include_dirs = [str(here), str(root / "include"), str(deps_prefix / "include")]
        # lib vs lib64: manylinux is RHEL-based, where CMAKE_INSTALL_LIBDIR
        # defaults to lib64, so never hardcode "lib".
        library_dirs = [str(core_dir)] + [
            str(p) for p in sorted(deps_prefix.glob("lib*")) if p.is_dir()
        ]

    std_args = ["/std:c++latest"] if OSTYPE == "Windows" else ["-std=c++23"]

    # abseil scatters constants and singletons (container_internal::kSooControl,
    # MixingHashState::kSeed, Mutex, Now, ...) across archive members that
    # nothing else references, so a normal -l link never pulls them in.  Python
    # extensions link with -undefined dynamic_lookup, so this does NOT fail the
    # link -- it fails later at dlopen with "symbol not found in flat
    # namespace", which is much harder to diagnose.  Force every abseil archive
    # in and let the linker dead-strip the remainder; resolving the symbols one
    # at a time is whack-a-mole.
    # MSVC emits absl_base.lib; Unix toolchains emit libabsl_base.a. Globbing
    # only the Unix shape silently yields NOTHING on Windows, link_args ends up
    # empty, and the force-load below never happens -- which does not fail the
    # link, it fails later at load time with a missing-symbol error that is far
    # harder to trace back to here.
    _absl_pattern = "absl_*.lib" if OSTYPE == "Windows" else "libabsl_*.a"
    absl_archives = [
        str(p)
        for d in library_dirs
        for p in sorted(pathlib.Path(d).glob(_absl_pattern))
    ]
    if not absl_archives:
        raise RuntimeError(
            f"no abseil archives matched {_absl_pattern!r} under {library_dirs}. "
            "Without force-loading them the extension links but fails at import "
            "with missing absl symbols; refusing to build a broken binding."
        )
    if OSTYPE == "Darwin":
        link_args = [f"-Wl,-force_load,{a}" for a in absl_archives]
        link_args.append("-Wl,-dead_strip")
    elif OSTYPE == "Linux":
        link_args = [
            "-Wl,--whole-archive",
            *absl_archives,
            "-Wl,--no-whole-archive",
            "-Wl,--gc-sections",
        ]
    else:
        link_args = [f"/WHOLEARCHIVE:{a}" for a in absl_archives]

    return cythonize(
        Extension(
            "d810.backends.cobra._cobra",
            [
                "src/d810/backends/cobra/_cobra.pyx",
                "src/d810/backends/cobra/cobra_shim.cpp",
            ],
            language="c++",
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=["cobra-core"],
            extra_compile_args=std_args,
            extra_link_args=link_args,
        ),
        compiler_directives={"language_level": "3", "binding": True},
    )


# Minimal setup() - everything else comes from pyproject.toml
setup(ext_modules=get_ext_modules() + get_cobra_ext_modules())
