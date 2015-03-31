VERSION ?= 1
COMPILER ?= ../Proj$(VERSION)
TESTS ?= ${CURDIR}
AS := nasm
ASFLAGS := $(ASFLAGS) -f elf64
CC := gcc
CFLAGS := $(CFLAGS) -ggdb -lm

OUTFILES := $(addsuffix .out, $(basename $(wildcard cases/*.in)))
ASMFILES := $(addsuffix .asm, $(basename $(wildcard cases/*.in)))
CHECKFILES := $(addsuffix .test, $(basename $(wildcard cases/*.in)))
CHECKS := $(addprefix check-, $(basename $(wildcard cases/*.in) .in))

all: tests

tests: $(OUTFILES) $(ASMFILES) $(COMPILER)

run-tests: tests $(CHECKS)

check-cases/test-%: cases/test-%.in cases/test-%.out cases/test-%.test
	@test -e $(addsuffix .stdin, $(basename $(word 1, $^) .in)) && \
	    ( $(word 2, $^) < $(addsuffix .stdin, $(basename $(word 1, $^) .in)) | diff $(word 3, $^) - || echo "^^^ $< FAILED" ) || \
	    ( $(word 2, $^) | diff $(word 3, $^) - || echo "^^^ $< FAILED" )

cases/test-%.asm: cases/test-%.in $(COMPILER)
	$(COMPILER) < $< > $@

cases/test-%.o: cases/test-%.asm
	$(AS) $(ASFLAGS) $<

cases/test-%.out: cases/test-%.o
	$(CC) $(CFLAGS) $< -o $@

clean:
	-$(RM) cases/*.out cases/*.o cases/*.asm
