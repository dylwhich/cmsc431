%{
#include <iostream>
#include <cmath>
#include <stdio.h>

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
 void oper_add();
 void oper_sub();
 void oper_mul();
 void oper_div();
 void oper_neg();
 void oper_mod();
 void asm_end();
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
expr '\n' { asm_end(); }
| expr '\n' expr
;

expr:
INTEGER           { asm_literal($1); }
| expr '+' expr   { oper_add(); }
| expr '-' expr   { oper_sub(); }
| expr '*' expr   { oper_mul(); }
| expr '/' expr   { oper_div(); }
| expr '%' expr   { oper_mod(); }
| '-' expr        { oper_neg(); }
| expr POW expr   { oper_add(); /* FIXME */ }
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
	 "    push QWORD rdx\n");
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

void call_printf() {
  printf("    mov rdi, fmt_decimal_nl\n"
	 "    pop rsi\n"
	 "    mov al, 0\n"
	 "    call printf\n");
}
	 
void asm_end() {
  call_printf();
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
    asm_func_header("main");
    return yyparse();
}
