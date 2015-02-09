%{
#include <iostream>
#include <cmath>
#include <stdio.h>
#include <string.h>

/* Parser error reporting routine */
void yyerror(const char *msg);

/* Scannar routine defined by Flex */
int yylex();

using namespace std;

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
 void asm_end();
 void asm_pow();
%}

/* yylval union type */
%union {
    long longval;
}

/* Miscellaneous token types */
%token <longval> INTEGER

/* Operators */
%left '+' '-'
%left '*' '/' '%'
%right UMINUS
%right POW

/* Nonterminal types */
%type <longval> expr

%%

start:
program { asm_end(); }

program:
expr '\n' { call_printf(); }
| program expr '\n' { call_printf(); }
;

expr:
INTEGER           { asm_literal($1); }
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
  printf("%s: QWORD %d\n");
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
  printf("    push QWORD %d\n", num);
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
  printf("    pop rax\n"
	 "    add [rsp], rax\n");
}

void oper_mul() {
  printf("    pop rax\n"
	 "    imul rax, [rsp]\n"
	 "    mov [rsp], rax\n");
}

void oper_sub() {
  printf("    pop rax\n"
	 "    sub [rsp], rax\n");
}

void oper_div() {
  printf("    pop rcx\n"
	 "    pop rax\n"
	 "    cqo\n"
	 "    idiv QWORD rcx\n"
	 "    push QWORD rax\n");
}

void oper_neg() {
  printf("    neg QWORD [rsp]\n");
}

void oper_mod() {
  printf("    pop rcx\n"
	 "    pop rax\n"
	 "    cqo\n"
	 "    idiv QWORD rcx\n"
	 "    push QWORD rbx\n");
}

void oper_pow() {
  asm_func_call("intpow", 2, 1);
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

void asm_pow() {
  asm_func_header("intpow");
  printf("    mov rcx, rdi\n"
	 "    mov rax, QWORD 1\n\n"

	 "    cmp rcx, 0\n" // skip the loop for zero-power
	 "    jz .end\n\n"

	 "    cmp rcx, 0\n" // check for invalid (for integers) input
	 "    jl .invalid\n\n"

	 "    jmp .loop\n"
	 "    .invalid:\n"
	 "    mov rax, 0\n"
	 "    jmp .end\n\n"

	 "    .loop:\n"
	 "    imul rax, rsi\n"
	 "    loop .loop\n"
	 "    .end:\n");
  asm_func_return_regval("rax"); // technically redundant but good for future
  asm_func_footer();
}

void call_printf() {
  printf("    mov rdi, fmt_decimal_nl\n"
	 "    pop rsi\n"
	 "    mov al, 0\n"
	 "    call printf\n");
}

void asm_end() {
  asm_func_footer();
}

void yyerror(const char *msg)
{
    cerr << "Parser error:\n" << msg << endl;
    exit(1);
}

int main()
{   
    asm_start();
    asm_pow();
    asm_func_header("main");
    return yyparse();
}
