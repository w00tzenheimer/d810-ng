ifeq ($(OS),Windows_NT)
	CC = clang  # Use clang on Windows
	RM = del /Q  # Windows delete command
	TARGET_LIB = ../bins/libobfuscated.dll  # Windows shared library
	TARGET_LIB_IDA = ../bins/libobfuscated.dll.i64
	LDFLAGS = -shared -Wl,/FORCE:UNRESOLVED -g  # Enable debug info
else
	CC = gcc  # C compiler for Unix-like systems
	RM = rm -f   # rm command
	TARGET_LIB = ../bins/libobfuscated.so  # target lib
	TARGET_LIB_IDA = ../bins/libobfuscated.so.i64  # target lib
	LDFLAGS = -shared -s # linking flags
endif

ifeq ($(OS),Windows_NT)
	CFLAGS = -Wall -Wextra -O0 -g  # C flags for Windows (no -fPIC)
else
	CFLAGS = -fPIC -Wall -Wextra -Og -g  # C flags for Unix-like systems
endif

SRCS = manually_obfuscated.c ollvm_obfuscated.c tigress_obfuscated.c constant_folding.c # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-$(RM) ${TARGET_LIB} ${TARGET_LIB_IDA} ${OBJS} $(SRCS:.c=.d)