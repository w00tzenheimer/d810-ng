#!/usr/bin/env bash
# Build the CoBRA static libs that d810's mba-solve binding links against.
#
# Runs from CIBW_BEFORE_ALL during wheel builds, and by hand for a local
# source build. Produces the layout setup.py expects under
# third_party/cobra:
#
#     build-deps/install/{lib*,include}/   abseil + highway
#     build/lib/core/libcobra-core.{a,lib}
#
# NO LLVM, NO Z3. The LLVM pass plugin is irrelevant to us and pulls in a
# multi-gigabyte dependency; Z3 is linked on the Python side instead, and
# letting CMake find a system Z3 here would bake a second, possibly different
# Z3 into the binding.
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/third_party/cobra}"

if [ ! -f "$ROOT/CMakeLists.txt" ]; then
    cat >&2 <<EOF
error: no CoBRA source at $ROOT

The submodule is not checked out. Either:
    git submodule update --init --recursive
or point COBRA_ROOT at your own CoBRA build tree and skip this script.
EOF
    exit 1
fi

for tool in cmake ninja; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required to build CoBRA from source" >&2
        exit 1
    }
done

cd "$ROOT"

# Dependencies first: CoBRA's own CMakeLists expects them installed.
if [ ! -d build-deps/install ]; then
    echo "==> building CoBRA dependencies (abseil + highway, no LLVM)"
    cmake -S dependencies -B build-deps -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCOBRA_BUILD_LLVM_PASS=OFF \
        -DCOBRA_ENABLE_Z3=OFF \
        -DCMAKE_INSTALL_PREFIX="$PWD/build-deps/install"
    cmake --build build-deps --target install
fi

if [ ! -d build/lib/core ]; then
    echo "==> building cobra-core"
    # DISABLE_FIND_PACKAGE_Z3 is belt-and-braces on top of COBRA_ENABLE_Z3=OFF:
    # a system Z3 on the build host must not get linked in behind our back.
    cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCOBRA_BUILD_LLVM_PASS=OFF \
        -DCOBRA_ENABLE_Z3=OFF \
        -DCMAKE_DISABLE_FIND_PACKAGE_Z3=ON \
        -DCMAKE_PREFIX_PATH="$PWD/build-deps/install"
    cmake --build build --target cobra-core
fi

# Fail loudly rather than let setup.py discover an empty tree later.
CORE=$(find build -type f \( -name 'libcobra-core.a' -o -name 'cobra-core.lib' \) | head -1 || true)
if [ -z "$CORE" ]; then
    echo "error: cobra-core static library not produced under $ROOT/build" >&2
    exit 1
fi
echo "==> cobra-core: $CORE"
echo "==> COBRA_ROOT=$ROOT"
