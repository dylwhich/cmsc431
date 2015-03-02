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
 void asm_literal(int);
 void asm_func_header(const char*);
 void asm_func_footer();
 void asm_func_call(const char*, int, int);
 void call_printf();
 void oper_add();
 void oper_sub();
 void oper_mul();
 void oper_div();
 void oper_neg();
 void oper_mod();
 void oper_pow();
%}

/* yylval union type */
%union {
  long longval;
  float floatval;
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
PRINT ID {
  char ref[64];
  char inst[80];

  symbol_get_reference(block_resolve_symbol(cur_scope, $2), ref);
  sprintf(inst, "mov rsi, %s", ref);

  statement_append_instruction(cur_stmt, inst);
  statement_append_instruction(cur_stmt,
			       "mov rdi, fmt_decimal_nl\n"
			       "mov al, 0\n"
			       "call printf");
}
| PRINT expr {
  statement_append_instruction(cur_stmt,
			       "mov rsi, QWORD [rsp]\n"
			       "mov rdi, fmt_decimal_nl\n"
			       "mov al, 0\n"
			       "call printf");
}

;

declare:
INTTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;
  st.type = PRIMITIVE;
  st.value.primitive = $1;

  sl.type = LABEL;

  block_add_symbol(cur_scope, $2, st, sl);
}
| FLOATTYPE ID
;

assign:
ID '=' expr
| ID '=' ID
;

expr:
INTEGER           { asm_literal($1); $$ = INTTYPE; }
| expr '+' expr   { oper_add(); }
| expr '-' expr   { oper_sub(); }
| expr '*' expr   { oper_mul(); }
| expr '/' expr   { oper_div(); }
| expr '%' expr   { oper_mod(); }
| '-' expr        { oper_neg(); }
| expr POW expr   { oper_pow(); }
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

/*void asm_const_char(const char *name, char *value) {
  int mode = 1, lastmode = 1;
  // 1: bare (unquoted character ids)
  // 0: quoted string literal
  printf("%s: ", name);
  while (*value) {
    lastmode = mode;
    if (*value >= 32 && *value < 127) {
      mode = 0;
    } else {
      mode = 1;
    }

    if (mode != lastmode) {
      if (mode == 1) {
	printf(", \"");
      } else if (mode == 0) {
	printf("\", ");
      }
    } else {
      if (mode == 1) {
	printf(", ");
      }
    }

    if (*value == '"') {
      printf("\\\"");
    } else if (*value >= 32 && *value < 127) {
      printf("%c", *value);
    } else {
      printf(
      }*/

void asm_literal(int num) {
  char tmp[32];
  sprintf(tmp, "push QWORD %d", num);
  statement_append_instruction(cur_stmt, tmp);
}

// This will generate a function header for a function that takes n args
// in the future, they will also get a type
// and also will somehow translate their names to registers / addresses
void asm_func_header(const char *name) {
  printf("%s:\n"
	 "    push rbp\n"
	 "    mov rbp, rsp\n",
	 name);
}

void asm_func_footer() {
  printf("    mov rsp, rbp\n"
	 "    pop rbp\n"
	 "    ret\n");
}

void oper_add() {
  statement_append_instruction(cur_stmt, "pop rax\nadd [rsp], rax");
}

void oper_mul() {
  statement_append_instruction(cur_stmt, "pop rax\nimul rax, [rsp]\nmov [rsp], rax");
}

void oper_sub() {
  statement_append_instruction(cur_stmt, "pop rax\nsub [rsp], rax");
}

void oper_div() {
  statement_append_instruction(cur_stmt, "pop rcx\npop rax\ncqo\nidiv QWORD rcx\npush QWORD rax");
}

void oper_neg() {
  statement_append_instruction(cur_stmt, "neg QWORD [rsp]");
}

void oper_mod() {
  statement_append_instruction(cur_stmt, "pop rcx\npop rax\ncqo\nidiv QWORD rcx\npush QWORD rbx");
}

void oper_pow() {
  statement_append_instruction(cur_stmt, "pop rdi\npop rsi\ncall intpow\npush rax");
}

void asm_func_call(const char *name, int nargs, int nrets) {
  int i;
  const char *reg;
  for (i=0; i < nargs; i++) {
    switch(i) {
    case 0:
      reg = "rdi";
      break;
    case 1:
      reg = "rsi";
      break;
    case 2:
      reg = "rdx";
      break;
    case 3:
      reg = "rcx";
      break;
    case 4:
      reg = "r8";
      break;
    case 5:
      reg = "r9";
      break;
    default:
      reg = NULL;
      break;
    }
    if (reg != NULL) {
      printf("    pop %s ; load argument %s(#%d)\n",
	     reg, name, i);
    } // otherwise just leave it on the stack
  }
  printf("    call %s ; call function %s\n", name, name);
  if (nrets) {
    printf("    push rax ; save return value on stack\n");
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

void call_printf() {
  printf("    mov rdi, fmt_decimal_nl\n"
	 "    pop rsi\n"
	 "    mov al, 0\n"
	 "    call printf\n");
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
