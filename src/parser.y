%{
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include "program.h"

/* Parser error reporting routine */
void yyerror(const char *msg);

/* Scannar routine defined by Flex */
int yylex();

 struct Block global_scope;
 struct Block *cur_scope;
 struct Symbol cur_symbol;
 struct Statement *cur_stmt;

/* Our functions */
 void asm_literal_int(int);
 void asm_literal_float(double);
 void asm_literal_string(const char*);
 void asm_literal_bool(char);
 void oper_add(enum yytokentype);
 void oper_sub(enum yytokentype);
 void oper_mul(enum yytokentype);
 void oper_div(enum yytokentype);
 void oper_neg(enum yytokentype);
 void oper_mod(enum yytokentype);
 void oper_pow(enum yytokentype);
 void type_check(enum yytokentype, enum yytokentype);
%}

/* yylval union type */
%union {
  long longval;
  double floatval;
  char boolval;
  char idval[64];
  char *stringval;
}

/* Miscellaneous token types */
%token <longval> INTEGER
%token <floatval> FLOAT
%token <boolval> BOOL
%token <stringval> STRING
%token <idval> ID
%token PRINT
%token PRINTL
%token <longval> INTTYPE
%token <floatval> FLOATTYPE
%token <boolval> BOOLTYPE
%token <stringval> STRINGTYPE
%token <longval> READINT
%token <floatval> READFLOAT

/* Operators */
%left '+' '-'
%left '*' '/' '%'
%right UMINUS
%right POW

/* Nonterminal types */
%type <longval> expr

%%

start: {
  block_init(&global_scope, "global", NULL);
  cur_scope = &global_scope;
 }
program {
  block_write(&global_scope, stdout);
  block_destroy(&global_scope);
  cur_scope = NULL;
}
;

program:
{ cur_stmt = block_add_statement(cur_scope); } stmt '\n' {  }
| program { cur_stmt = block_add_statement(cur_scope); } stmt '\n' { }
;

stmt:
expr
| declare
| assign
| print_stmt
;

print_stmt:
PRINTL expr {
  switch ($2) {
  case INTTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_decimal_nl");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "movq xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 1");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_float_nl");
    break;
  case STRINGTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_string_nl");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case BOOLTYPE:
    statement_append_instruction(cur_stmt, "mov rdi, bool_str_true_nl");
    statement_append_instruction(cur_stmt, "mov rax, bool_str_false_nl");
    statement_append_instruction(cur_stmt, "cmp QWORD [rsp], QWORD 0");
    statement_append_instruction(cur_stmt, "cmovz rdi, rax");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  default:
    printf("; I DON'T KNOW %d\n", $2);
    break;
  }
  statement_stack_align(cur_stmt);
  statement_append_instruction(cur_stmt, "call printf");
  statement_stack_reset(cur_stmt);
}
| PRINT expr {
  switch ($2) {
  case INTTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_decimal");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "movq xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 1");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_float");
    break;
  case STRINGTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_string");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case BOOLTYPE:
    statement_append_instruction(cur_stmt, "mov rdi, bool_str_true");
    statement_append_instruction(cur_stmt, "mov rax, bool_str_false");
    statement_append_instruction(cur_stmt, "cmp QWORD [rsp], QWORD 0");
    statement_append_instruction(cur_stmt, "cmovz rdi, rax");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  default:
    printf("; I DON'T KNOW %d\n", $2);
    break;
  }
  statement_stack_align(cur_stmt);
  statement_append_instruction(cur_stmt, "call printf");
  statement_stack_reset(cur_stmt);
}
;

declare:
// TODO combine these somehow
INTTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;

  if (block_resolve_symbol(cur_scope, $2) != NULL) {
    fprintf(stderr, "Symbol %s:\n", $2);
    yyerror("Double declaration invalid");
  }

  st.type = PRIMITIVE;
  st.value.primitive = INTTYPE;

  sl.type = LABEL;

  block_add_symbol(cur_scope, $2, st, sl);
}
| FLOATTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;

  if (block_resolve_symbol(cur_scope, $2) != NULL) {
    fprintf(stderr, "Symbol %s:\n", $2);
    yyerror("Double declaration invalid");
  }

  sl.type = PRIMITIVE;
  st.value.primitive = FLOATTYPE;

  sl.type = LABEL;
  block_add_symbol(cur_scope, $2, st, sl);
}
| BOOLTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;

  if (block_resolve_symbol(cur_scope, $2) != NULL) {
    fprintf(stderr, "Symbol %s:\n", $2);
    yyerror("Double declaration invalid");
  }

  st.type = PRIMITIVE;
  st.value.primitive = BOOLTYPE;

  sl.type = LABEL;

  block_add_symbol(cur_scope, $2, st, sl);
}
;

assign:
ID '=' expr {
  char ref[64];
  char inst[80];
  struct Symbol *target = block_resolve_symbol(cur_scope, $1);

  if (target == NULL) {
    yyerror("Unknown identifier");
  } else {
    if (target->type.type == PRIMITIVE) {
      if (target->type.value.primitive != $3) {
	yyerror("Incompatible types");
      } else {
	symbol_get_reference(target, ref);
	printf("; reference to %s is %s\n", target->label, ref);
	sprintf(inst, "mov %s, rax; %s = <stmt>", ref, target->label);
	statement_pop(cur_stmt, RAX);
	statement_append_instruction(cur_stmt, inst);
      }
    }
  }
}
;

expr:
INTEGER           { asm_literal_int($1); $$ = INTTYPE; }
| FLOAT           { asm_literal_float($1); $$ = FLOATTYPE; }
| BOOL            { asm_literal_bool($1); $$ = BOOLTYPE; }
| STRING          { asm_literal_string($1); $$ = STRINGTYPE; }
| READINT {
  statement_push(cur_stmt, RAX);
  statement_append_instruction(cur_stmt, "mov rsi, rsp");
  statement_append_instruction(cur_stmt, "mov rdi, fmt_input_int");
  statement_append_instruction(cur_stmt, "mov al, 0");
  statement_append_instruction(cur_stmt, "call scanf");
  $$ = INTTYPE;
}
| READFLOAT {
  // push a dummy value onto the stack
  statement_append_instruction(cur_stmt, "xor rax, rax");
  statement_push(cur_stmt, RAX);
  statement_append_instruction(cur_stmt, "lea rsi, [rsp]");
  statement_append_instruction(cur_stmt, "mov rdi, fmt_input_float");
  statement_append_instruction(cur_stmt, "mov al, 0");

  statement_append_instruction(cur_stmt, "call scanf");

  $$ = FLOATTYPE;
}
| ID {
  char ref[64];
  char inst[80];
  struct Symbol *target = block_resolve_symbol(cur_scope, $1);
  if (target == NULL) {
    yyerror("Unknown identifier");
  } else {
    if (target->type.type == PRIMITIVE) {
      symbol_get_reference(target, ref);
      printf("; reference to %s is %s\n", target->label, ref);
      sprintf(inst, "mov rax, %s; deref %s", ref, target->label);
      statement_append_instruction(cur_stmt, inst);
      statement_push(cur_stmt, RAX);
    }
  }
  $$ = block_resolve_symbol(cur_scope, $1)->type.value.primitive;
}
| expr '+' expr   { type_check($1, $3); $$ = $3; oper_add($$); }
| expr '-' expr   { type_check($1, $3); $$ = $3; oper_sub($$); }
| expr '*' expr   { type_check($1, $3); $$ = $3; oper_mul($$); }
| expr '/' expr   { type_check($1, $3); $$ = $3; oper_div($$); }
| expr '%' expr   { type_check($1, $3); $$ = $3; oper_mod($$); }
| '-' expr        { $$ = $2; oper_neg($$); }
| expr POW expr   { type_check($1, $3); $$ = $3; oper_pow($$); }
| '(' expr ')'    { $$ = $2; }
;

%%

void asm_literal_int(int num) {
  statement_push_int(cur_stmt, num);
}

void asm_literal_float(double num) {
  char tmp[64], tmp2[64];
  struct Symbol *symbol;

  sprintf(tmp, "%lf", num);

  block_get_unique_name(cur_scope, tmp2);
  symbol = block_add_symbol_initialized(cur_scope, tmp2, FLOATTYPE, tmp);

  symbol_get_reference(symbol, tmp2);
  sprintf(tmp, "mov rax, %s", tmp2);

  statement_append_instruction(cur_stmt, tmp);
  statement_push(cur_stmt, RAX);
}

void asm_literal_string(const char *str) {
  char tmp[64], tmp2[64];
  struct Symbol *symbol;

  statement_append_instruction(cur_stmt, ";;+asm_literal_string\n");

  block_get_unique_name(cur_scope, tmp);
  symbol = block_add_symbol_initialized(cur_scope, tmp, STRINGTYPE, str);

  symbol_get_reference(symbol, tmp);
  sprintf(tmp2, "lea rax, %s", tmp);

  statement_append_instruction(cur_stmt, tmp2);
  statement_push(cur_stmt, RAX);

  statement_append_instruction(cur_stmt, ";;-asm_literal_string\n");
}

void asm_literal_bool(char val) {
  statement_push_int(cur_stmt, val);
}

void oper_add(enum yytokentype type) {
  switch (type) {
  case INTTYPE:
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "add [rsp], rax");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");

    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "faddp st1");
    statement_stack_reset(cur_stmt);

    statement_append_instruction(cur_stmt, "fstp QWORD [rsp]");
    break;
  }
}

void oper_mul(enum yytokentype type) {
  switch(type) {
  case INTTYPE:
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt,"imul rax, [rsp]\n"
				 "mov [rsp], rax");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");

    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "fmulp st1");
    statement_stack_reset(cur_stmt);

    statement_append_instruction(cur_stmt, "fstp QWORD [rsp]");
    break;
  }
}

void oper_sub(enum yytokentype type) {
  switch(type) {
  case INTTYPE:
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "sub [rsp], rax");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "fsubrp st1");
    statement_stack_reset(cur_stmt);

    statement_append_instruction(cur_stmt, "fstp QWORD [rsp]");
    break;
  }
}

void oper_div(enum yytokentype type) {
  switch(type) {
  case INTTYPE:
    statement_pop(cur_stmt, RCX);
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "cqo\n"
				 "idiv QWORD rcx");
    statement_push(cur_stmt, RAX);
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "fdivrp");
    statement_stack_reset(cur_stmt);
    statement_append_instruction(cur_stmt, "fstp QWORD [rsp]");
    break;
  }
}

void oper_neg(enum yytokentype type) {
  switch(type) {
  case INTTYPE:
    statement_append_instruction(cur_stmt, "neg QWORD [rsp]");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_append_instruction(cur_stmt, "fchs");
    statement_append_instruction(cur_stmt, "fstp QWORD [rsp]");
    break;
  }
}

void oper_mod(enum yytokentype type) {
  switch(type) {
  case INTTYPE:
    statement_pop(cur_stmt, RCX);
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "cqo\n"
				 "idiv QWORD rcx");
    statement_push(cur_stmt, RBX);
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "movq xmm1, QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "movq xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 2");
    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "call fmod");
    statement_stack_reset(cur_stmt);
    statement_append_instruction(cur_stmt, "movq QWORD [rsp], xmm0");
    break;
  }
}

void oper_pow(enum yytokentype type) {
  switch(type) {
  case INTTYPE:
    statement_pop(cur_stmt, RDI);
    statement_pop(cur_stmt, RSI);
    statement_append_instruction(cur_stmt, "call intpow");
    statement_push(cur_stmt, RAX);
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "movq xmm1, QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "movq xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 2");

    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "call pow");
    statement_stack_reset(cur_stmt);

    statement_append_instruction(cur_stmt, "movq QWORD [rsp], xmm0");
    break;
  }
}

void type_check(enum yytokentype a, enum yytokentype b) {
  if (a != b) {
    yyerror("Incompatible Types");
  }
}

void yyerror(const char *msg)
{
  fprintf(stderr, "Parser error:\n    %s\n", msg);
  exit(1);
}

int main()
{   
    return yyparse();
}
