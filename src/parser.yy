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
 void asm_builtin_add();
 void asm_builtin_sub();
 void asm_builtin_mul();
 void asm_builtin_div();
 void asm_builtin_neg();
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
expr '\n' { cout << $1 << endl; }
;

expr:
INTEGER           { asm_literal($1); }
| expr '+' expr   { asm_builtin_add(); }
| expr '-' expr   { asm_builtin_sub(); }
| expr '*' expr   { asm_builtin_mul(); }
| expr '/' expr   { asm_builtin_div(); }
| expr '%' expr   { asm_builtin_add(); /* FIXME */ }
| '-' expr        { asm_builtin_neg(); }
| expr POW expr   { asm_builtin_add(); }
| '(' expr ')'    { $$ = $2; }
;

%%

void asm_start() {
  printf("    extern printf\n\n"
	 "    SECTION .data\n"
	 "fmt_decimal_nl:\n"
	 "    db \"%%ld\", 10, 0\n\n"
	 "    SECTION .text\n"
	 "    global main\n");
}

void asm_literal(int num) {
  printf("    push QWORD %d\n", num);
}

// This will generate a function header for a function that takes n args
// in the future, they will also get a type
// and also will somehow translate their names to registers / addresses
void asm_func_header(int nargs) {
  printf("intpow:\n"
	 "    push rbp\n"
	 "    mov rbp, rsp\n");
}

void asm_func_footer() {
  printf("    mov rsp, rbp\n"
	 "    pop rbp\n"
	 "    ret\n");
}

void asm_builtin_add() {
  printf("    pop rax\n"
	 "    add [rsp], rax\n");
}

void asm_builtin_mul() {
  printf("    pop rax\n"
	 "    imul rax, [rsp]\n"
	 "    mov [rsp], rax\n");
}

void asm_builtin_sub() {
  printf("    pop rax\n"
	 "    sub [rsp], rax\n");
}

void asm_builtin_div() {
  printf("    pop rcx\n"
	 "    pop rax\n"
	 "    cqo\n"
	 "    idiv QWORD rcx\n"
	 "    push QWORD rdx\n");
}

void asm_builtin_neg() {
  printf("    neg QWORD [rsp]\n");
}

void asm_end() {
  printf("    mov rdi, fmt_decimal_nl\n"
	 "    pop rsi\n"
	 "    mov al, 0\n"
	 "    call printf"
	 "    mov rsp, rbp\n"
	 "    mov rbp\n"
	 "    ret");
}

void yyerror(const char *msg)
{
    cerr << "Parser error:\n" << msg << endl;
    exit(1);
}

int main()
{
    return yyparse();
}
