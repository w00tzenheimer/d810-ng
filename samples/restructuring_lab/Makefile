# Restructuring lab — self-contained build.
#
# Compiles c/*.c (MinGW clang) + assembles masm/*.asm (llvm-ml64) and links them
# into bins/restructuring_lab.dll. Runs INSIDE the `restructuring-lab` Docker
# image (see build_lab.sh); `/include` is the read-only samples/include mount.
# This Makefile only ever touches its own dir -- it never references the parent
# samples tree, so it cannot clobber libobfuscated.
#
# Toolchain lessons carried over from the libobfuscated MASM work:
#   * real/llvm ml64 wants `/nologo /c /Fo<obj> <asm>` (NOT -m64)
#   * under a MinGW/MSYS shell, `/`-options get path-mangled -> MSYS2_ARG_CONV_EXCL

CC      ?= clang
ML64    ?= llvm-ml64
TRIPLE  := x86_64-w64-mingw32
OUT     := bins/restructuring_lab.dll

CFLAGS  := --target=$(TRIPLE) -fuse-ld=lld -O0 -g -ffreestanding -fno-inline \
           -fno-builtin -I/include -DD810_DLL_EXPORT=1 -Wall -Wextra -Wno-error
LDFLAGS := --target=$(TRIPLE) -shared -fuse-ld=lld -Wl,--export-all-symbols

C_SRCS   := $(wildcard c/*.c)
ASM_SRCS := $(wildcard masm/*.asm)
C_OBJS   := $(patsubst c/%.c,build/%.o,$(C_SRCS))
ASM_OBJS := $(patsubst masm/%.asm,build/%.obj,$(ASM_SRCS))

.PHONY: all clean
all: $(OUT)

$(OUT): $(C_OBJS) $(ASM_OBJS) | bins
	@echo "[lab] linking $@"
	$(CC) $(LDFLAGS) -o $@ $(C_OBJS) $(ASM_OBJS)
	@file $@ || true

build/%.o: c/%.c | build
	@echo "[lab] cc $<"
	$(CC) $(CFLAGS) -c -o $@ $<

build/%.obj: masm/%.asm | build
	@echo "[lab] ml64 $<"
	MSYS2_ARG_CONV_EXCL='*' $(ML64) /nologo /c /Fo$@ $<

build bins:
	mkdir -p $@

clean:
	rm -rf build bins
