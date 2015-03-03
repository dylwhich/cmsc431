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
 void asm_start();
 void asm_literal_int(int);
 void asm_literal_float(double);
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
  char idval[64];
}

/* Miscellaneous token types */
%token <longval> INTEGER
%token <floatval> FLOAT
%token <idval> ID
%token PRINT
%token <longval> INTTYPE
%token <floatval> FLOATTYPE

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
PRINT expr {
  switch ($2) {
  case INTTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_decimal_nl");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "movlps xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 1");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_float_nl");
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
INTTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;
  st.type = PRIMITIVE;
  //printf("st.value.primitive = %d\n", INTTYPE);
  st.value.primitive = INTTYPE;

  sl.type = LABEL;

  block_add_symbol(cur_scope, $2, st, sl);
}
| FLOATTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;
  sl.type = PRIMITIVE;
  st.value.primitive = FLOATTYPE;

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

void asm_start() {
  printf("    extern printf\n\n"

	 "    SECTION .data\n"
	 "fmt_decimal_nl:\n"
	 "    db \"%%ld\", 10, 0\n\n"

	 "    SECTION .text\n"
	 "    global main\n\n");
}

void asm_const_int(const char *name, int value) {
  printf("%s: QWORD %d\n", name, value);
}

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
    statement_append_instruction(cur_stmt, "movlps xmm1, QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "movlps xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 2");
    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "call fmod");
    statement_stack_reset(cur_stmt);
    statement_append_instruction(cur_stmt, "movlps QWORD [rsp], xmm0");
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
    statement_append_instruction(cur_stmt, "movlps xmm1, QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "movlps xmm0, QWORD [rsp]");
    statement_append_instruction(cur_stmt, "mov al, 2");
    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "call pow");
    statement_stack_reset(cur_stmt);
    statement_append_instruction(cur_stmt, "movlps QWORD [rsp], xmm0");
    break;
  }
}

void type_check(enum yytokentype a, enum yytokentype b) {
  if (a != b) {
    yyerror("Incompatible Types");
  }
}

void asm_func_return_regval(const char *reg) {
  if (strcmp(reg, "rax")) {
    printf("    mov rax, %s ; return_regval(%s)\n", reg, reg);
  }
}

void asm_func_return_const(int val) {
  printf("    mov rax, QWORD %d ; return_const(%d)\n", val, val);
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
