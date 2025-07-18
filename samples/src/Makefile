ifeq ($(OS),Windows_NT)
	CC = clang  # Use clang on Windows
	RM = del /Q  # Windows delete command
	TARGET_LIB = ../bins/libobfuscated.dll  # Windows shared library
	TARGET_LIB_IDA = ../bins/libobfuscated.dll.i64
	LDFLAGS = -shared
else
	CC = gcc  # C compiler for Unix-like systems
	RM = rm -f   # rm command
	TARGET_LIB = ../bins/libobfuscated.so  # target lib
	TARGET_LIB_IDA = ../bins/libobfuscated.so.i64  # target lib
	LDFLAGS = -shared   # linking flags
endif

CFLAGS = -fPIC -Wall -Wextra -Og -g  # C flags

SRCS = manually_obfuscated.c ollvm_obfuscated.c tigress_obfuscated.c # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -s -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-$(RM) ${TARGET_LIB} ${TARGET_LIB_IDA} ${OBJS} $(SRCS:.c=.d)