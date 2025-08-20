ifeq ($(OS),Windows_NT)
UNAME_S :=
else
UNAME_S := $(shell uname -s)
endif

# Target selection: allow cross-targeting. Defaults to building a Windows DLL
# for x86_64 as requested. Set TARGET_OS to one of: windows, darwin, linux or
# "native" to pick the host OS. Set TARGET_ARCH to x86_64, x86, arm, etc.
# You can also set BUILD_ARCH to avoid clashing with make's built-in TARGET_ARCH.
TARGET_OS ?= windows
TARGET_ARCH ?= x86_64
BUILD_ARCH ?=
CURDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CURDIR := $(patsubst %/,%,$(CURDIR))

# Binary name for output (without extension); can be overridden by user
BINARY_NAME ?= libobfuscated

# Host OS (lowercase) used for naming the artifact
ifeq ($(OS),Windows_NT)
HOST_OS := windows
else ifeq ($(UNAME_S),Darwin)
HOST_OS := darwin
else
HOST_OS := linux
endif


# Normalize empty TARGET_OS to default windows
ifeq ($(strip $(TARGET_OS)),)
  TARGET_OS := windows
endif

# If user requested native target, map to the detected host
ifeq ($(TARGET_OS),native)
  ifeq ($(OS),Windows_NT)
    TARGET_OS := windows
  else ifeq ($(UNAME_S),Darwin)
    TARGET_OS := darwin
  else
    TARGET_OS := linux
  endif
endif

# Minimal arch flags: allow either a raw arch name (x86_64/x86/arm64) or an
# explicit compiler flag (like -m64 or -arch x86_64). Prefer ARCH_FLAGS from
# env; else normalize the requested arch. Prefer BUILD_ARCH over TARGET_ARCH.
RAW_ARCH := $(if $(strip $(BUILD_ARCH)),$(strip $(BUILD_ARCH)),$(strip $(TARGET_ARCH)))
# Compute a normalized arch name for artifact naming
ifeq ($(strip $(RAW_ARCH)),)
  NORM_ARCH := x86_64
else ifneq (,$(findstring x86_64,$(RAW_ARCH)))
  NORM_ARCH := x86_64
else ifneq (,$(findstring amd64,$(RAW_ARCH)))
  NORM_ARCH := x86_64
else ifneq (,$(findstring arm64,$(RAW_ARCH)))
  NORM_ARCH := arm64
else ifneq (,$(findstring aarch64,$(RAW_ARCH)))
  NORM_ARCH := arm64
else ifneq (,$(findstring i386,$(RAW_ARCH)))
  NORM_ARCH := x86
else ifneq (,$(findstring i686,$(RAW_ARCH)))
  NORM_ARCH := x86
else ifneq (,$(findstring -m32,$(RAW_ARCH)))
  NORM_ARCH := x86
else ifneq (,$(findstring x86,$(RAW_ARCH)))
  NORM_ARCH := x86
else
  # Fallback: use RAW_ARCH as-is without spaces
  NORM_ARCH := $(subst $(space),,$(RAW_ARCH))
endif
ifeq ($(strip $(ARCH_FLAGS)),)
  ifneq (,$(filter -%,$(RAW_ARCH)))
    ARCH_FLAGS := $(RAW_ARCH)
  else ifeq ($(UNAME_S),Darwin)
    # On macOS, use -arch for architecture selection
    ifeq ($(RAW_ARCH),x86_64)
      ARCH_FLAGS := -arch x86_64
    else ifeq ($(RAW_ARCH),x86)
      ARCH_FLAGS := -arch i386
    else ifeq ($(RAW_ARCH),arm64)
      ARCH_FLAGS := -arch arm64
    else
      ARCH_FLAGS :=
    endif
  else
    # On non-Darwin, use -m32/-m64 where applicable
    ifeq ($(RAW_ARCH),x86_64)
      ARCH_FLAGS := -m64
    else ifeq ($(RAW_ARCH),x86)
      ARCH_FLAGS := -m32
    else
      ARCH_FLAGS :=
    endif
  endif
endif

# Clear the built-in TARGET_ARCH so implicit rules don't append a stray token
override TARGET_ARCH :=

# Host tool choices (used for commands like rm/cc on the build machine)
ifeq ($(OS),Windows_NT)
CC = clang  # Use clang on Windows host
RM = del /Q  # Windows delete command
else
CC = gcc  # C compiler for Unix-like systems
RM = rm -f   # rm command
endif

# Configure output extension based on desired target OS
ifeq ($(TARGET_OS),windows)
OUTPUT_EXT := dll
else ifeq ($(TARGET_OS),darwin)
OUTPUT_EXT := dylib
else
OUTPUT_EXT := so
endif

# If user provided BINARY_NAME via env or command line, output is just that
# name with the suffix. Otherwise, include host and arch for clarity.
ifneq (,$(filter environment command line,$(origin BINARY_NAME)))
TARGET_LIB = bins/$(BINARY_NAME).$(OUTPUT_EXT)
else
TARGET_LIB = bins/$(BINARY_NAME)_$(HOST_OS)_$(NORM_ARCH).$(OUTPUT_EXT)
endif
TARGET_LIB_IDA = $(TARGET_LIB).i64

# Linker flags should match the host toolchain for compatibility
ifeq ($(OS),Windows_NT)
LDFLAGS = -shared -Wl,/FORCE:UNRESOLVED -g $(ARCH_FLAGS)
else ifeq ($(UNAME_S),Darwin)
LDFLAGS = -shared -undefined dynamic_lookup $(ARCH_FLAGS)
else
LDFLAGS = -shared -Wl,--unresolved-symbols=ignore-in-shared-libs $(ARCH_FLAGS)
endif

ifeq ($(OS),Windows_NT)
CFLAGS = -Wall -Wextra $(ARCH_FLAGS) -O0 -g -Iinclude -fno-inline -fno-builtin -fno-vectorize -fno-slp-vectorize  # C flags for Windows (no -fPIC)
else
# Add include directory and include arch flags so the compiler receives
# normalized flags (e.g. -m64) instead of a raw arch token. Disable optimizations fully.
CFLAGS = -fPIC -Wall -Wextra $(ARCH_FLAGS) -O0 -g -Iinclude -fno-inline -fno-builtin -fno-vectorize -fno-slp-vectorize    # C flags for Unix-like systems
endif

# C sources are now under src/c
SRCS = $(wildcard src/c/*.c)
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

# Explicit compile rule to avoid implicit one that uses built-in TARGET_ARCH
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

-include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-$(RM) ${TARGET_LIB} ${TARGET_LIB_IDA} ${OBJS} $(SRCS:.c=.d)


