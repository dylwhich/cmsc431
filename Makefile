export VERSION := 3
export ROOT := ${CURDIR}
export SRC := $(ROOT)/src
export TESTS := $(ROOT)/tests
export COMPILER := $(ROOT)/Proj$(VERSION)

.PHONY: tests

all: $(COMPILER)

$(COMPILER): $(SRC)/Calc
	mv $(SRC)/Calc $(COMPILER)

$(SRC)/Calc:
	$(MAKE) -C $(SRC)

tests: $(COMPILER)
	$(MAKE) -C $(TESTS)

check: $(COMPILER)
	$(MAKE) -C $(TESTS) run-tests

clean:
	-$(RM) $(COMPILER)
	$(MAKE) -C $(SRC) clean
	$(MAKE) -C $(TESTS) clean
