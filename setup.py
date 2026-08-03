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


# IDA SDK 9.4 stopped shipping lib/x64_win_qt, the prebuilt namespaced Qt6
# import libraries, and the GitHub SDK this file downloads has never carried
# them for 9.4. ida-qt-libs republishes them, built with QT_NAMESPACE=QT and
# symbol-for-symbol identical to the last set Hex-Rays shipped.
IDA_QT_REPO = "mahmoudimus/ida-qt-libs"
DEFAULT_QT_DIR = pathlib.Path(__file__).parent / ".ida-qt"

# IDA SDK version -> matching release. Each IDA release pins a specific Qt
# version, so the artifact is chosen by SDK rather than hardcoded. 9.3 and 9.4
# both ship Qt 6.8.2 and their import libraries are currently byte-identical,
# but that is a coincidence of those two releases, not a rule.
IDA_QT_TAGS = {
    930: "ida-9.3-qt-6.8.2-win64",
    940: "ida-9.4.0-qt-6.8.2-win64",
}


def _ida_qt_tag(sdk_version: int) -> str:
    """Return the ida-qt-libs release matching *sdk_version*."""
    known = IDA_QT_TAGS.get(int(sdk_version))
    if known:
        return known

    newest = IDA_QT_TAGS[max(IDA_QT_TAGS)]
    print(
        f"WARNING: no ida-qt-libs release recorded for SDK {sdk_version}; "
        f"falling back to {newest}. If that IDA ships a different Qt version "
        "the ABI will not match - set IDA_QT explicitly, or see "
        f"https://github.com/{IDA_QT_REPO}/releases",
        file=sys.stderr,
    )
    return newest


def _download_ida_qt(dest: pathlib.Path, tag: str) -> pathlib.Path:
    """Download and checksum-verify an ida-qt-libs release into *dest*."""
    import hashlib
    import zipfile

    base = f"https://github.com/{IDA_QT_REPO}/releases/download/{tag}"
    dest.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(f"{base}/SHA256SUMS") as response:
        checksums = {
            parts[1]: parts[0]
            for parts in (
                line.split() for line in response.read().decode().splitlines()
            )
            if len(parts) == 2
        }

    archive = dest / f"{tag}.zip"
    if not archive.is_file():
        print(f"Downloading {tag} from {IDA_QT_REPO}...", file=sys.stderr)
        urllib.request.urlretrieve(f"{base}/{tag}.zip", archive)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    expected = checksums.get(archive.name)
    if digest != expected:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"Checksum mismatch for {archive.name}: "
            f"expected {expected}, got {digest}"
        )

    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(dest)
    print(f"Qt import libraries extracted to: {dest / tag}", file=sys.stderr)
    return dest / tag


def ensure_ida_qt(sdk_path: pathlib.Path, sdk_version: int) -> pathlib.Path | None:
    """Return a directory containing Qt6*.lib, or None if unavailable.

    Resolution order:
      1. ``IDA_QT`` - an extracted ida-qt-libs release, or any directory of
         namespaced Qt import libraries.
      2. The SDK's own ``lib/x64_win_qt``, present through SDK 9.3.
      3. A downloaded ida-qt-libs release, unless ``IDA_QT_NO_DOWNLOAD`` is set.
    """
    override = os.environ.get("IDA_QT")
    if override:
        candidate = pathlib.Path(override)
        for path in (candidate / "lib", candidate):
            if path.is_dir() and any(path.glob("Qt6*.lib")):
                return path
        raise FileNotFoundError(f"IDA_QT={override} contains no Qt6*.lib")

    bundled = _sdk_lib_dir(sdk_path, "x64_win_qt")
    if bundled.is_dir() and any(bundled.glob("Qt*.lib")):
        print(f"Using SDK-bundled Qt at: {bundled}", file=sys.stderr)
        return bundled

    if os.environ.get("IDA_QT_NO_DOWNLOAD"):
        print(
            "No Qt import libraries found and IDA_QT_NO_DOWNLOAD is set",
            file=sys.stderr,
        )
        return None

    tag = _ida_qt_tag(sdk_version)
    extracted = DEFAULT_QT_DIR / tag
    if not (extracted / "lib").is_dir():
        extracted = _download_ida_qt(DEFAULT_QT_DIR, tag)
    return extracted / "lib"


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
    try:
        tarball_url = f"https://github.com/HexRaysSA/ida-sdk/archive/refs/heads/{IDA_SDK_BRANCH}.tar.gz"
        print(f"Downloading {tarball_url}...", file=sys.stderr)

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            urllib.request.urlretrieve(tarball_url, tmp.name)

            with tarfile.open(tmp.name, "r:gz") as tar:
                with tempfile.TemporaryDirectory() as tmpdir:
                    try:
                        tar.extractall(tmpdir, filter="data")
                    except TypeError:
                        tar.extractall(tmpdir)
                    extracted = next(pathlib.Path(tmpdir).iterdir())
                    shutil.move(str(extracted), str(DEFAULT_SDK_DIR))

            os.unlink(tmp.name)

        print(f"IDA SDK downloaded to: {DEFAULT_SDK_DIR}", file=sys.stderr)
        return DEFAULT_SDK_DIR

    except Exception as e:
        raise RuntimeError(
            f"Failed to download IDA SDK: {e}\n"
            f"Please manually clone: git clone {IDA_SDK_REPO} {DEFAULT_SDK_DIR}\n"
            f"Or set IDA_SDK environment variable to your SDK location."
        )


def get_compile_args(sdk_version: int = 0):
    """Return platform-specific compilation arguments."""
    if OSTYPE == "Windows":
        standard_args = ["/std:c++17"] if int(sdk_version) >= 940 else []
        # Qt 6 headers require MSVC conformance mode. Without
        # /Zc:__cplusplus MSVC reports __cplusplus as 199711L whatever /std:
        # says and qcompilerdetection.h raises C1189; without /permissive-
        # ADL resolves Qt's comparesEqual/compareThreeWay ambiguously (C2666)
        # and an incomplete QString trips C2139.
        qt_args = ["/Zc:__cplusplus", "/permissive-"]
        return (
            ["/TP", "/EHa"]
            + standard_args
            + qt_args
            + (["/Z7", "/Od"] if DEBUG else [])
        )
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

        qt_dir = ensure_ida_qt(IDA_SDK, sdk_version)
        if qt_dir is None:
            raise RuntimeError(
                "No Qt import libraries found. IDA SDK 9.4 no longer ships "
                "lib/x64_win_qt. Set IDA_QT to an extracted release from "
                f"https://github.com/{IDA_QT_REPO}/releases, or unset "
                "IDA_QT_NO_DOWNLOAD to fetch one automatically."
            )
        library_dirs.append(str(qt_dir))

        # An ida-qt-libs release carries matching headers alongside lib/; the
        # SDK's own x64_win_qt does not.
        qt_include = qt_dir.parent / "include"
        if qt_include.is_dir():
            include_dirs.append(str(qt_include))

        # Qt6 for IDA 9.2+ (SDK >= 920), Qt5 for older
        if sdk_version >= 920:
            qt_ver = "Qt6"
        else:
            qt_ver = "Qt5"
        libraries = [
            f"{qt_ver}Core",
            f"{qt_ver}Gui",
            f"{qt_ver}Widgets",
            "ida",
            "idalib",
        ]
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


# Minimal setup() - everything else comes from pyproject.toml
setup(ext_modules=get_ext_modules())
