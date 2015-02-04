VERSION ?= 1
COMPILER ?= ../Proj$(VERSION)
TESTS ?= ${CURDIR}
AS := nasm
ASFLAGS := $(ASFLAGS) -f elf64
CC := gcc

OUTFILES := $(addsuffix .out, $(basename $(wildcard cases/*.in)))
ASMFILES := $(addsuffix .asm, $(basename $(wildcard cases/*.in)))
TESTS := $(addprefix check-, $(basename $(wildcard cases/*.in) .in))

all: tests

tests: $(OUTFILES) $(ASMFILES) $(TESTS)

check-cases/test-%: cases/test-%.in cases/test-%.out
#	@echo -n "Testing $<: "
#	@head $<
	@test "`bc < $<`" -eq "`$(word 2, $^)`" || echo "$< FAILED"

cases/test-%.asm: cases/test-%.in
	$(COMPILER) < $< > $@

cases/test-%.o: cases/test-%.asm
	$(AS) $(ASFLAGS) $<

cases/test-%.out: cases/test-%.o
	$(CC) $< -o $@

clean:
	-$(RM) cases/*.out cases/*.o cases/*.asm