# Object files
objs := scanner.o parser.tab.o

# Libraries to link with executable calculator program
LDLIBS := -lfl -L.

# Program to run instead of lex
LEX := flex

# Program to run instead of yacc
YACC := bison

# Flags to pass to YACC program
YFLAGS := -d

# Link objects and build executable
Calc: $(objs)
	$(CC) $(objs) $(LDLIBS) -o $@

# Compile scanner to object file
scanner.o: scanner.c parser.tab.h

# Compile parser to object file
parser.tab.o: parser.tab.c

# Build scanner implementation from flex file
scanner.c: scanner.l
	$(LEX) -o $@ $<

# Build *.tab.* files from bison file
parser.tab.h parser.tab.c: parser.y
	$(YACC) $(YFLAGS) $<

# Remove compilation artifacts
.PHONY: clean
clean:
	-$(RM) *.o *.tab.* scanner.c Calc
