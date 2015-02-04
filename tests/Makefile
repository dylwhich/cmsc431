VERSION ?= 1
COMPILER ?= ../Proj$(VERSION)
ALL_VERS = `seq 1..$(VERSION)`
TESTS ?= ${CURDIR}
BIN ?= $(TESTS)/bin
TESTS_PJ1 := $(addsuffix .out, $(basename $(wildcard proj-1/*.in)))

current: tests-proj$(VERSION)

all:
	$(foreach VER,$(ALL_VERS),test-proj$(VER))

tests-proj1: $(TESTS_PJ1)

proj-1/test-%.out: proj-1/test-%.in
	$(COMPILER) < $< > $@

#tests-proj1: $(TESTS)/proj-$(VERSION)/*.in
#	$(foreach TESTCASE,$?,`bash -c $(COMPILER) < $(TESTCASE) > bin/$@-\`basename $(TESTCASE) .in\`.out`)

clean:
	-$(RM) $(TESTS)/proj-*/*.out