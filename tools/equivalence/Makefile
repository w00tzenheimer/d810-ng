# Equivalence harness for sub_7FFD3338C040
# Builds a single binary that links ref + ours + harness against shared mock.

CC      ?= cc
CFLAGS  ?= -O0 -g -Wall -Wno-unused-variable -Wno-unused-but-set-variable \
           -Wno-unused-function -Wno-pointer-to-int-cast \
           -Wno-int-to-pointer-cast -Wno-shift-count-overflow \
           -Wno-int-conversion -Wno-incompatible-pointer-types \
           -Wno-overflow -Wno-parentheses -Wno-shift-negative-value \
           -Wno-tautological-constant-out-of-range-compare \
           -fno-strict-aliasing -fno-strict-overflow

OBJ = mock.o ref.o ours.o harness.o

all: harness

harness: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c mock.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) harness

.PHONY: all clean
