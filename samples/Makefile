# ==============================================================================
# Universal Clang-First Cross-Platform Makefile (Linux ↔ Windows ↔ macOS) – 2025
#
# Features
# • Always uses Clang / clang-cl / Apple clang
# • Cross-compiles perfect Windows DLLs from Linux or macOS (lld + MinGW target)
# • Builds pure x86_64 macOS dylibs even on Apple Silicon
# • Ignores undefined symbols the correct way on every platform
# • Extremely forgiving architecture selection (see examples below)
# • Full debug info, zero optimizations, no inlining/vectorization
# • Single Makefile – works everywhere, no conditionals needed per host
#
# Usage examples (from the samples directory)
#   make                                 # → Windows x86_64 DLL (default)
#   make TARGET_OS=linux                 # → Linux .so for host arch
#   make TARGET_OS=darwin BUILD_ARCH=x86_64   # → pure Intel macOS dylib
#   make TARGET_OS=darwin BUILD_ARCH=arm64    # → Apple Silicon dylib
#   make BUILD_ARCH=x86                  # → maps to x86_64 (32-bit builds unsupported)
#   make BINARY_NAME=myplugin            # → bins/myplugin.dll (no host/arch suffix)
#   make clean
#   make test-all-platforms              # → Build and test all 4 platforms (Windows/Linux/macOS x86_64/macOS arm64)
#   NIX_DEBUG_SYMBOLS=True make TARGET_OS=darwin  # → Generate dSYM bundle for macOS
#   NIX_DEBUG_SYMBOLS=True make TARGET_OS=linux   # → Generate .debug file for Linux
# Note: Windows PDB files are always generated. macOS dSYM and Linux .debug files require NIX_DEBUG_SYMBOLS=True
# ==============================================================================

# ----------------------------- Host detection -----------------------------
ifeq ($(OS),Windows_NT)
    UNAME_S :=
    HOST_OS := windows
    RM      := del /Q 2>NUL || ver>NUL
    MKDIR   := mkdir
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        HOST_OS := darwin
    else
        HOST_OS := linux
    endif
    RM      := rm -f
    MKDIR   := mkdir -p
endif

# ----------------------------- User configurable options -----------------------------
# windows | darwin | linux | native
TARGET_OS    ?= windows
# x86_64 | x86 (mapped to x86_64) | arm64 | aarch64 | -m64 | -arch arm64 | etc.
BUILD_ARCH   ?= x86_64
# libobfuscated by default
BINARY_NAME  ?= libobfuscated

# ----------------------------- Normalize target OS -----------------------------
RAW_TARGET_OS := $(strip $(TARGET_OS))
ifeq ($(RAW_TARGET_OS),native)
    TARGET_OS_NORMALIZED := $(HOST_OS)
else
    TARGET_OS_NORMALIZED := $(RAW_TARGET_OS)
endif
# Command-line variables override regular assignments in make; use override so
# TARGET_OS=native is always normalized to the detected host OS.
override TARGET_OS := $(TARGET_OS_NORMALIZED)

# ----------------------------- Super-friendly architecture handling -----------------------------
RAW_ARCH := $(or $(BUILD_ARCH),x86_64)

# Normalized name for filename (bins/libobfuscated_linux_x86_64.dll)
NORM_ARCH := $(strip \
    $(if $(findstring arm64,$(RAW_ARCH)),arm64,\
    $(if $(findstring aarch64,$(RAW_ARCH)),arm64,\
    x86_64)))

# Convert to real compiler flags Clang understands, per target OS
# If the user gave explicit flags (e.g. "-m64" or "-arch arm64"), trust them.
ARCH_FLAGS :=
ifneq ($(filter -%,$(RAW_ARCH)),)
    ARCH_FLAGS := $(RAW_ARCH)
else
    # Plain architecture name → choose flags based on TARGET_OS
    ifeq ($(TARGET_OS),darwin)
        NORM_FLAG_x86_64 := -arch x86_64
        NORM_FLAG_arm64  := -arch arm64
        ARCH_FLAGS := $(NORM_FLAG_$(NORM_ARCH))
    else ifeq ($(TARGET_OS),linux)
        NORM_FLAG_x86_64 := -m64
        ARCH_FLAGS := $(NORM_FLAG_$(NORM_ARCH))
    else ifeq ($(TARGET_OS),windows)
        # For MinGW cross, the architecture is encoded in the triple
        # (aarch64-w64-mingw32 vs x86_64-w64-mingw32), so we leave ARCH_FLAGS empty.
        ARCH_FLAGS :=
    endif
endif

# Prevent Make's built-in rules from injecting garbage
override TARGET_ARCH :=

# ----------------------------- Toolchain selection (Clang everywhere) -----------------------------
CC_BASE := clang

# On Windows host → prefer clang-cl.exe (MSVC-compatible) if it exists
ifeq ($(HOST_OS),windows)
    ifneq ($(shell where clang-cl.exe 2>NUL),)
        CC_BASE     := clang-cl.exe
        USING_CLANG_CL := 1
    endif
endif

# Check if we should use Docker for cross-builds
USE_DOCKER := 0
USE_DOCKER_WINDOWS := 0
USE_DOCKER_LINUX := 0
IN_LINUX_DOCKER ?= 0
LINUX_DOCKER_PLATFORM := $(if $(filter arm64,$(NORM_ARCH)),linux/arm64,linux/amd64)
LINUX_BUILD_IMAGE := linux-build-$(NORM_ARCH)
ifeq ($(TARGET_OS),windows)
    ifneq ($(USING_CLANG_CL),1)
        MINGW_SYSROOT ?=
        ifeq ($(MINGW_SYSROOT),)
            # Check if docker is available
            ifneq ($(shell command -v docker 2>/dev/null),)
                USE_DOCKER := 1
                USE_DOCKER_WINDOWS := 1
            endif
        endif
    endif
else ifeq ($(TARGET_OS),linux)
    ifneq ($(HOST_OS),linux)
        # On non-Linux hosts, prefer Docker so TARGET_OS=linux yields real ELF output.
        ifneq ($(shell command -v docker 2>/dev/null),)
            USE_DOCKER := 1
            USE_DOCKER_LINUX := 1
        endif
    endif
endif

# Target-specific compiler/linker selection
ifeq ($(TARGET_OS),windows)
    ifneq ($(USING_CLANG_CL),1)
        # Cross-compiling to Windows → MinGW target + lld
        ifeq ($(NORM_ARCH),arm64)
            TRIPLE := aarch64-w64-mingw32
        else
            TRIPLE := x86_64-w64-mingw32
        endif
        CC  := $(CC_BASE) --target=$(TRIPLE) -fuse-ld=lld
        LD  := $(CC_BASE) --target=$(TRIPLE) -fuse-ld=lld
        MINGW_SYSROOT ?=
        ifeq ($(MINGW_SYSROOT),)
            # Only show warnings if we're actually building (not just cleaning)
            ifeq ($(filter clean,$(MAKECMDGOALS)),)
                ifeq ($(USE_DOCKER),0)
                    $(warning [Makefile] No MinGW / Windows sysroot specified (MINGW_SYSROOT is empty))
                    $(warning [Makefile] To cross-compile to Windows from macOS/Linux you must first install a Windows toolchain.)
                    # Host-specific hints
                    ifeq ($(HOST_OS),darwin)
                        $(warning [Makefile] Detected host: macOS (Darwin). Example setup with Homebrew:)
                        $(warning [Makefile]   brew install llvm-mingw)
                        $(warning [Makefile] Then build with:)
                        $(warning [Makefile]   make TARGET_OS=windows MINGW_SYSROOT=$$(brew --prefix llvm-mingw))
                    else ifeq ($(HOST_OS),linux)
                        $(warning [Makefile] Detected host: Linux. Example setup on Debian/Ubuntu:)
                        $(warning [Makefile]   sudo apt-get update && sudo apt-get install -y mingw-w64)
                        $(warning [Makefile] Then point MINGW_SYSROOT at the MinGW prefix (e.g. /usr or /usr/x86_64-w64-mingw32).)
                        $(warning [Makefile]   make TARGET_OS=windows MINGW_SYSROOT=/usr)
                    endif
                    $(warning [Makefile] ------------------------------------------------------------)
                    $(warning [Makefile] NOTE: This Makefile is used for decompilation samples.)
                    $(warning [Makefile] If you only need the sample to compile, you may simply remove)
                    $(warning [Makefile] or comment out the offending '#include <stdlib.h>' (or similar))
                    $(warning [Makefile] in the generated C file. Most samples do not actually need it.)
                    $(warning [Makefile] ------------------------------------------------------------)
                    $(warning [Makefile] Continuing without a sysroot — Clang may still fail later when)
                    $(warning [Makefile] attempting to include Windows headers like <stdlib.h>.)
                endif
            endif
        else
            CC := $(CC) --sysroot=$(MINGW_SYSROOT)
            LD := $(LD) --sysroot=$(MINGW_SYSROOT)
            MINGW_INCLUDEDIR ?= $(MINGW_SYSROOT)/include
            MINGW_LIBDIR     ?= $(MINGW_SYSROOT)/lib
        endif
    else
        CC  := $(CC_BASE)
        LD  := $(CC_BASE)
    endif
    OUTPUT_EXT := dll
else ifeq ($(TARGET_OS),darwin)
    CC  := $(CC_BASE)
    LD  := $(CC_BASE)
    OUTPUT_EXT := dylib
else
    ifeq ($(IN_LINUX_DOCKER),1)
        # Docker flow pins container CPU architecture via --platform, so native
        # clang in-container emits the requested ELF architecture.
        CC  := $(CC_BASE)
        LD  := $(CC_BASE)
    else ifeq ($(NORM_ARCH),arm64)
        TRIPLE := aarch64-linux-gnu
        CC  := $(CC_BASE) --target=$(TRIPLE)
        LD  := $(CC_BASE) --target=$(TRIPLE)
        LINUX_SYSROOT ?= /usr/aarch64-linux-gnu
        ifneq ($(USE_DOCKER_LINUX),1)
            ifeq ($(wildcard $(LINUX_SYSROOT)),)
                $(error [Makefile] Linux arm64 build requires sysroot at $(LINUX_SYSROOT). Set LINUX_SYSROOT explicitly, or use Docker TARGET_OS=linux with BUILD_ARCH=arm64)
            else
                CC := $(CC) --sysroot=$(LINUX_SYSROOT)
                LD := $(LD) --sysroot=$(LINUX_SYSROOT)
            endif
        endif
    else
        CC  := $(CC_BASE)
        LD  := $(CC_BASE)
    endif
    OUTPUT_EXT := so
endif

# Apply architecture flags
CC := $(CC) $(ARCH_FLAGS)
LD := $(LD) $(ARCH_FLAGS)

# ----------------------------- Output naming -----------------------------
ifneq ($(origin BINARY_NAME),default)
    TARGET_LIB := bins/$(BINARY_NAME).$(OUTPUT_EXT)
else
    TARGET_LIB := bins/$(BINARY_NAME)_$(HOST_OS)_$(NORM_ARCH).$(OUTPUT_EXT)
endif

# ----------------------------- Compiler & Linker flags (your exact debug setup) -----------------------------
CFLAGS_BASE := -Wall -Wextra \
               -O0 -g -Iinclude \
               -fno-inline -fno-builtin \
               -fno-vectorize -fno-slp-vectorize \
               -fno-omit-frame-pointer

ifeq ($(TARGET_OS),windows)
    ifeq ($(USING_CLANG_CL),1)
        # Native Windows with clang-cl (MSVC mode)
        CFLAGS  := /W3 /Od /Z7 /Iinclude /MDd /DD810_DLL_EXPORT=1
        # These samples are analysis artifacts and may intentionally keep
        # unresolved externals; /NOENTRY avoids requiring DllMain/CRT entry.
        LDFLAGS := /DLL /DEBUG:FULL /FORCE:UNRESOLVED /NOENTRY
    else
        # Cross-compile with Clang → MinGW
        CFLAGS  := $(CFLAGS_BASE) -DD810_DLL_EXPORT=1
        ifneq ($(MINGW_INCLUDEDIR),)
            CFLAGS  += -I$(MINGW_INCLUDEDIR)
        endif
        LDFLAGS := -shared -fuse-ld=lld \
                   -Wl,--export-all-symbols \
                   -Wl,--enable-auto-import
        ifneq ($(MINGW_LIBDIR),)
            LDFLAGS += -L$(MINGW_LIBDIR)
        endif
    endif
else
    # Linux / macOS
    CFLAGS  := $(CFLAGS_BASE) -fPIC $(ARCH_FLAGS)

    ifeq ($(TARGET_OS),darwin)
        LDFLAGS := -shared -undefined dynamic_lookup $(ARCH_FLAGS)
    else
        LDFLAGS := -shared $(ARCH_FLAGS)
    endif
endif

# Keep debug symbols in the final binary everywhere
ifeq ($(TARGET_OS),windows)
    ifneq ($(USING_CLANG_CL),1)
        LDFLAGS += -g
    endif
else
    LDFLAGS += -g
endif

# Platform-specific debug symbol file generation
ifeq ($(TARGET_OS),windows)
    ifneq ($(USING_CLANG_CL),1)
        # For MinGW cross-compilation, generate CodeView debug info and PDB
        CFLAGS += -gcodeview
        LDFLAGS += -Wl,--pdb=$(TARGET_LIB:.dll=.pdb)
    endif
endif

# ----------------------------- Sources & Objects -----------------------------
# Exclude mba_hard.c from the default build - it has its own binary (libmba_hard)
# and contains symbols that duplicate those in manually_obfuscated.c
# SRCS := $(filter-out src/c/mba_hard.c src/c/sub_7FFC1EB47830.c,$(wildcard src/c/*.c))
SRCS := $(wildcard src/c/*.c)
ifeq ($(USING_CLANG_CL),1)
OBJS := $(SRCS:.c=.obj)
AUTO_EXPORTS_RSP := bins/auto_exports.rsp
else
OBJS := $(SRCS:.c=.o)
endif

# ----------------------------- Rules -----------------------------
.PHONY: all clean docker-windows-dockerfile docker-windows-setup docker-linux-dockerfile docker-linux-setup docker-windows-build test-all-platforms

# If using Docker, intercept and run in container.
ifeq ($(USE_DOCKER_WINDOWS),1)
all: docker-windows-setup
	@echo "[Makefile] Using Docker for Windows cross-compilation..."
	@docker run --rm -v "$$PWD":/work win-build sh -c "make USE_DOCKER=1 clean && make TARGET_OS=windows BUILD_ARCH=$(BUILD_ARCH) BINARY_NAME=$(BINARY_NAME) NIX_DEBUG_SYMBOLS=$(NIX_DEBUG_SYMBOLS)"
else ifeq ($(USE_DOCKER_LINUX),1)
all: docker-linux-setup
	@echo "[Makefile] Using Docker for Linux cross-compilation..."
	@docker run --rm --platform $(LINUX_DOCKER_PLATFORM) -v "$$PWD":/work $(LINUX_BUILD_IMAGE) sh -c "make USE_DOCKER=1 clean && make TARGET_OS=linux BUILD_ARCH=$(BUILD_ARCH) BINARY_NAME=$(BINARY_NAME) NIX_DEBUG_SYMBOLS=$(NIX_DEBUG_SYMBOLS) IN_LINUX_DOCKER=1"
else
all: bins $(TARGET_LIB)
endif

bins:
	@$(MKDIR) bins >/dev/null 2>&1 || $(MKDIR) bins

# Build target - MSVC/clang-cl vs GCC/Clang
ifeq ($(USING_CLANG_CL),1)
$(AUTO_EXPORTS_RSP): $(OBJS) | bins
	@echo "Generating auto-export list ($@)"
	@powershell -NoProfile -ExecutionPolicy Bypass -File scripts/generate_auto_exports.ps1 \
		-OutFile "$@" \
		-Objects "$(OBJS)"

$(TARGET_LIB): $(OBJS) $(AUTO_EXPORTS_RSP)
	@echo "Linking $(TARGET_LIB)"
	link.exe /nologo /OUT:$@ $(OBJS) $(LDFLAGS) @$(AUTO_EXPORTS_RSP)

%.obj: %.c
	$(CC) /nologo $(CFLAGS) /c /Fo:$@ $<
else ifeq ($(CC),cl)
$(TARGET_LIB): $(OBJS)
	$(CC) $(LDFLAGS) /Fe:$@ $^

%.obj: %.c
	$(CC) $(CFLAGS) /c /Fo:$@ $<
else
$(TARGET_LIB): $(OBJS)
	@echo "Linking $(TARGET_LIB)"
	$(LD) $(LDFLAGS) -o $@ $^
	@if [ "$(TARGET_OS)" = "darwin" ]; then \
		if [ "$(NIX_DEBUG_SYMBOLS)" = "True" ]; then \
			echo "Generating dSYM bundle..."; \
			dsymutil $@ -o $@.dSYM 2>/dev/null || echo "  (dsymutil not found, skipping dSYM generation)"; \
		else \
			echo "  (dSYM generation skipped; set NIX_DEBUG_SYMBOLS=True to generate)"; \
		fi; \
	elif [ "$(TARGET_OS)" = "linux" ]; then \
		if [ "$(NIX_DEBUG_SYMBOLS)" = "True" ]; then \
			OBJCOPY_CMD=$$(command -v objcopy 2>/dev/null || command -v llvm-objcopy 2>/dev/null || echo ""); \
			if [ -n "$$OBJCOPY_CMD" ]; then \
				echo "Generating separate debug symbols..."; \
				$$OBJCOPY_CMD --only-keep-debug $@ $@.debug 2>/dev/null && \
				$$OBJCOPY_CMD --add-gnu-debuglink=$@.debug $@ 2>/dev/null && \
				echo "  ✓ Created: $@.debug" || echo "  (objcopy failed, debug symbols remain in binary)"; \
			else \
				echo "  (objcopy/llvm-objcopy not found, debug symbols remain embedded in binary with -g)"; \
			fi; \
		else \
			echo "  (separate .debug file generation skipped; set NIX_DEBUG_SYMBOLS=True to generate)"; \
		fi; \
	fi

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
endif

ifneq ($(USING_CLANG_CL),1)
ifneq ($(USE_DOCKER),1)
# Dependency generation (optional but nice)
$(SRCS:.c=.d): %.d: %.c
	$(CC) $(CFLAGS) -MM -MT $(@:.d=.o) $< > $@

-include $(SRCS:.c=.d)
endif
endif

clean:
	-$(RM) $(TARGET_LIB) $(OBJS) $(SRCS:.c=.d) $(AUTO_EXPORTS_RSP) 2>/dev/null || true

# ---------------------------------------------------------------------------
# Optional helper: generate a simple Dockerfile for Windows cross-builds
# ---------------------------------------------------------------------------
docker-windows-dockerfile:
	@echo "Writing Dockerfile.windows (Debian + clang + lld + mingw-w64 + make)..."
	@{ \
		echo "FROM debian:stable-slim"; \
		echo "RUN apt-get update && apt-get install -y clang lld mingw-w64 make && rm -rf /var/lib/apt/lists/*"; \
		echo "WORKDIR /work"; \
		echo "CMD [\"make\", \"TARGET_OS=windows\", \"MINGW_SYSROOT=/usr\"]"; \
	} > Dockerfile.windows
	@echo "Created Dockerfile.windows."
	@echo "Build the image with:"
	@echo "  docker build -t win-build -f Dockerfile.windows ."
	@echo "Then run your Windows build with:"
	@echo "  docker run --rm -v \"$$PWD\":/work win-build"

# ---------------------------------------------------------------------------
# Auto-setup Docker for Windows builds
# ---------------------------------------------------------------------------
docker-windows-setup: docker-windows-dockerfile
	@if ! docker images -q win-build 2>/dev/null | grep -q .; then \
		echo "[Makefile] Building Docker image 'win-build' (this may take a few minutes on first run)..."; \
		if docker build -t win-build -f Dockerfile.windows . > /dev/null 2>&1; then \
			echo "[Makefile] ✓ Docker image 'win-build' ready."; \
		else \
			echo "[Makefile] Error: Failed to build Docker image. Check Dockerfile.windows and try again."; \
			exit 1; \
		fi; \
	else \
		echo "[Makefile] ✓ Docker image 'win-build' already exists."; \
	fi

# ---------------------------------------------------------------------------
# Optional helper: generate a simple Dockerfile for Linux cross-builds
# ---------------------------------------------------------------------------
docker-linux-dockerfile:
	@echo "Writing Dockerfile.linux (Alpine + clang + lld + make for ELF builds)..."
	@{ \
		echo "FROM alpine:3.20"; \
		echo "RUN apk add --no-cache clang lld make musl-dev gcc binutils file"; \
		echo "WORKDIR /work"; \
		echo "CMD [\"make\", \"TARGET_OS=linux\"]"; \
	} > Dockerfile.linux
	@echo "Created Dockerfile.linux."
	@echo "Build the image with:"
	@echo "  docker build --platform linux/amd64 -t linux-build-x86_64 -f Dockerfile.linux ."
	@echo "  docker build --platform linux/arm64 -t linux-build-arm64 -f Dockerfile.linux ."
	@echo "Then run your Linux build with:"
	@echo "  docker run --rm --platform linux/amd64 -v \"$$PWD\":/work linux-build-x86_64"

# ---------------------------------------------------------------------------
# Auto-setup Docker for Linux builds
# ---------------------------------------------------------------------------
docker-linux-setup: docker-linux-dockerfile
	@if ! docker images -q $(LINUX_BUILD_IMAGE) 2>/dev/null | grep -q .; then \
		echo "[Makefile] Building Docker image '$(LINUX_BUILD_IMAGE)' (this may take a few minutes on first run)..."; \
		if docker build --platform $(LINUX_DOCKER_PLATFORM) -t $(LINUX_BUILD_IMAGE) -f Dockerfile.linux . > /dev/null 2>&1; then \
			echo "[Makefile] ✓ Docker image '$(LINUX_BUILD_IMAGE)' ready."; \
		else \
			echo "[Makefile] Error: Failed to build Docker image. Check Dockerfile.linux and try again."; \
			exit 1; \
		fi; \
	else \
		echo "[Makefile] ✓ Docker image '$(LINUX_BUILD_IMAGE)' already exists."; \
	fi

# ---------------------------------------------------------------------------
# Build and test all platforms
# ---------------------------------------------------------------------------
test-all-platforms:
	@echo "=========================================="
	@echo "Building and testing all platforms..."
	@echo "=========================================="
	@echo ""
	@echo "[1/4] Testing Windows (x86_64) via Docker..."
	@if command -v docker >/dev/null 2>&1; then \
		docker run --rm -v "$$PWD":/work win-build sh -c "make clean && make TARGET_OS=windows" > /tmp/win-build.log 2>&1 && \
		echo "  ✓ Windows build successful" || \
		(echo "  ✗ Windows build failed:" && tail -10 /tmp/win-build.log && exit 1); \
	else \
		echo "  ⚠ Docker not found, skipping Windows build"; \
	fi
	@echo ""
	@echo "[2/4] Testing Linux (x86_64)..."
	@$(MAKE) clean TARGET_OS=linux > /tmp/linux-build.log 2>&1 && \
		$(MAKE) TARGET_OS=linux >> /tmp/linux-build.log 2>&1 && \
		echo "  ✓ Linux build successful" && \
		test -f bins/libobfuscated.so && echo "  ✓ Created: bins/libobfuscated.so" || \
		(echo "  ✗ Linux build failed:" && tail -10 /tmp/linux-build.log && exit 1)
	@echo ""
	@echo "[3/4] Testing macOS (x86_64)..."
	@$(MAKE) clean TARGET_OS=darwin BUILD_ARCH=x86_64 > /tmp/darwin-x86_64-build.log 2>&1 && \
		$(MAKE) TARGET_OS=darwin BUILD_ARCH=x86_64 >> /tmp/darwin-x86_64-build.log 2>&1 && \
		echo "  ✓ macOS x86_64 build successful" && \
		test -f bins/libobfuscated.dylib && echo "  ✓ Created: bins/libobfuscated.dylib" || \
		(echo "  ✗ macOS x86_64 build failed:" && tail -10 /tmp/darwin-x86_64-build.log && exit 1)
	@echo ""
	@echo "[4/4] Testing macOS (arm64)..."
	@$(MAKE) clean TARGET_OS=darwin BUILD_ARCH=arm64 > /tmp/darwin-arm64-build.log 2>&1 && \
		$(MAKE) TARGET_OS=darwin BUILD_ARCH=arm64 >> /tmp/darwin-arm64-build.log 2>&1 && \
		echo "  ✓ macOS arm64 build successful" && \
		test -f bins/libobfuscated.dylib && echo "  ✓ Created: bins/libobfuscated.dylib" || \
		(echo "  ✗ macOS arm64 build failed:" && tail -10 /tmp/darwin-arm64-build.log && exit 1)
	@echo ""
	@echo "=========================================="
	@echo "✓ All platforms built successfully!"
	@echo "=========================================="
	@echo ""
	@echo "Generated files:"
	@ls -lh bins/*.dll bins/*.so bins/*.dylib 2>/dev/null | awk '{print "  " $$9 " (" $$5 ")"}' || true
