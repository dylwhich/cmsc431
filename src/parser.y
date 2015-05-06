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

 struct Statement *recursive_find_first_statement(struct SubBlock*);
 struct Statement *recursive_find_last_statement(struct SubBlock*);
 void if_stmt(struct Block*, struct Statement*,
	      struct SubBlock*, struct SubBlock*);
 void while_loop(struct Block*, struct Statement*, struct SubBlock*);

 void oper_bool_or(enum yytokentype, enum yytokentype);
 void oper_bool_and(enum yytokentype, enum yytokentype);
 void oper_bool_xor(enum yytokentype, enum yytokentype);
 void oper_bool_eq(enum yytokentype, enum yytokentype);
 void oper_bool_neq(enum yytokentype, enum yytokentype);
 void oper_bool_lt(enum yytokentype, enum yytokentype);
 void oper_bool_le(enum yytokentype, enum yytokentype);
 void oper_bool_gt(enum yytokentype, enum yytokentype);
 void oper_bool_ge(enum yytokentype, enum yytokentype);
 void oper_bool_not(enum yytokentype);

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
%token <stringval> FUNCDEF
%token <idval> ID
%token PRINT
%token PRINTL
%token NOP
%token VOID
%left IF
%nonassoc ELSE
%token WHILE
%token <longval> INTTYPE
%token <floatval> FLOATTYPE
%token <boolval> BOOLTYPE
%token <stringval> STRINGTYPE
%token <idval> FUNCTYPE
%token <longval> READINT
%token <floatval> READFLOAT

/* Operators */
%left BOOL_OR
%left BOOL_AND
%left BOOL_XOR
%left BOOL_EQUAL BOOL_NOT_EQUAL
%left '<' BOOL_LESS_EQUAL '>' BOOL_GREATER_EQUAL
%left '+' '-'
%left '*' '/' '%'
%right UMINUS '!'
%right POW

/* Nonterminal types */
%type <longval> expr
%type <longval> assign
%type <longval> any_type

%%

start: {
  block_init(&global_scope, "global", NULL);
  cur_scope = &global_scope;
 }
multi_stmt {
  block_write(&global_scope, stdout);
  block_destroy(&global_scope);
  cur_scope = NULL;
}
;

multi_stmt:
%empty
| multi_stmt stmt
;

multi_expr:
%empty
| multi_expr expr ','
;

arg_list:
'(' multi_expr ')'
| '(' VOID ')'
;

multi_type:
%empty
| multi_type any_type ',';

any_type:
INTTYPE { $$ = $1;} | FLOATTYPE { $$ = $1;} | BOOLTYPE { $$ = $1;} | STRINGTYPE { $$ = $1;};

param_list:
'(' multi_type ')'
| '(' VOID ')'
| '(' ')';

func_call: '.' ID arg_list;

func_decl: FUNCDEF ID param_list stmt;

stmt:
block
| if_else_stmt
| while_loop
| { cur_stmt = block_add_statement(cur_scope); } print_stmt ';'
| { cur_stmt = block_add_statement(cur_scope); } declare ';'
| { cur_stmt = block_add_statement(cur_scope); } func_decl
| { cur_stmt = block_add_statement(cur_scope); } expr ';'
| func_call {printf(";;aaaaa\n"); cur_stmt = block_add_statement(cur_scope); } ';'
| NOP { cur_stmt = block_add_statement(cur_scope); } ';'
;

block:
'{' { cur_scope = block_add_child(cur_scope); }
multi_stmt { cur_scope = cur_scope->parent; } '}'
;

while_loop:
{
  // Add a new statement for the test-expression
  cur_scope = block_add_child(cur_scope);
  cur_stmt = block_add_statement(cur_scope);
} WHILE '(' expr ')' stmt {
  struct SubBlock *last_child = block_get_last_child(cur_scope);
  while_loop(cur_scope, &(subblock_get_prev(last_child)->value.statement),
	     last_child);
  cur_scope = cur_scope->parent;
}
;

/*if-stmt:
{
  cur_scope = block_add_child(cur_scope);
  cur_stmt = block_add_statement(cur_scope);
} IF '(' expr ')' stmt {
  struct SubBlock *last_child = block_get_last_child(cur_scope);
  if_stmt(cur_scope,
	  &(subblock_get_prev(last_child)->value.statement),
	  last_child, NULL);
  cur_scope = cur_scope->parent;
}
;*/

if_else_stmt:
{
  // Add a new statement for the test-expression
  cur_scope = block_add_child(cur_scope);
  cur_stmt = block_add_statement(cur_scope);
} IF '(' expr ')' stmt ELSE stmt {
  struct SubBlock *last_child = block_get_last_child(cur_scope);
  if_stmt(cur_scope,
	  &(subblock_get_prev(subblock_get_prev(last_child))->value.statement),
	  subblock_get_prev(last_child), last_child);
  cur_scope = cur_scope->parent;
}
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
    printf("; I DON'T KNOW %ld\n", $2);
    break;
  }
  statement_stack_align(cur_stmt);
  statement_append_instruction(cur_stmt, "call printf");
  statement_stack_reset(cur_stmt);
}
| PRINT expr {
  statement_call_setup(cur_stmt);
  switch ($2) {
  case INTTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "fmt_decimal");
    statement_call_arg_hacky(cur_stmt, 0, "QWORD [rsp]");
    break;
  case FLOATTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "fmt_float");
    statement_call_arg_hacky(cur_stmt, 1, "QWORD [rsp]");
    break;
  case STRINGTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "fmt_string");
    statement_call_arg_hacky(cur_stmt, 0, "QWORD [rsp]");
    break;
  case BOOLTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "rbx");
    break;
  default:
    printf("; I DON'T KNOW %ld\n", $2);
    break;
  }
  statement_call_finish(cur_stmt, "printf");
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

  sl.type = LOCAL;

  block_add_symbol(cur_scope, $2, st, sl);
}
| FLOATTYPE ID {
  struct SymbolType st;
  struct StorageLocation sl;

  if (block_resolve_symbol(cur_scope, $2) != NULL) {
    fprintf(stderr, "Symbol %s:\n", $2);
    yyerror("Double declaration invalid");
  }

  st.type = PRIMITIVE;
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

  sl.type = LOCAL;

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

	$$ = $3;
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
| func_call {
  $$ = INTTYPE;
}
| assign { $$ = $1; }
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
| expr BOOL_OR expr            { $$ = BOOLTYPE; oper_bool_or($1, $3); }
| expr BOOL_AND expr           { $$ = BOOLTYPE; oper_bool_and($1, $3); }
| expr BOOL_XOR expr           { $$ = BOOLTYPE; oper_bool_xor($1, $3); }
| expr BOOL_EQUAL expr         { $$ = BOOLTYPE; oper_bool_eq($1, $3); }
| expr BOOL_NOT_EQUAL expr     { $$ = BOOLTYPE; oper_bool_neq($1, $3); }
| expr '<' expr                { $$ = BOOLTYPE; oper_bool_lt($1, $3); }
| expr BOOL_LESS_EQUAL expr    { $$ = BOOLTYPE; oper_bool_le($1, $3); }
| expr '>' expr                { $$ = BOOLTYPE; oper_bool_gt($1, $3); }
| expr BOOL_GREATER_EQUAL expr { $$ = BOOLTYPE; oper_bool_ge($1, $3); }

| expr '+' expr   { type_check($1, $3); $$ = $3; oper_add($$); }
| expr '-' expr   { type_check($1, $3); $$ = $3; oper_sub($$); }
| expr '*' expr   { type_check($1, $3); $$ = $3; oper_mul($$); }
| expr '/' expr   { type_check($1, $3); $$ = $3; oper_div($$); }
| expr '%' expr   { type_check($1, $3); $$ = $3; oper_mod($$); }
| '-' expr        { $$ = $2; oper_neg($$); }
| '!' expr        { $$ = BOOLTYPE; oper_bool_not($2); }
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

  statement_append_instruction(cur_stmt, ";;+asm_literal_string");

  block_get_unique_name(&global_scope, tmp);
  symbol = block_add_symbol_initialized(&global_scope, tmp, STRINGTYPE, str);

  symbol_get_reference(symbol, tmp);
  sprintf(tmp2, "lea rax, %s", tmp);

  statement_append_instruction(cur_stmt, tmp2);
  statement_push(cur_stmt, RAX);

  statement_append_instruction(cur_stmt, ";;-asm_literal_string");
}

void asm_literal_bool(char val) {
  statement_push_int(cur_stmt, val);
}

void cmp_bools(enum yytokentype a, enum yytokentype b) {
  statement_pop(cur_stmt, RDX);
  statement_pop(cur_stmt, RAX);
  statement_append_instruction(cur_stmt, "cmp rax, rdx");
}

struct Statement *recursive_find_first_statement(struct SubBlock *stmt) {
  if (stmt->type == STATEMENT) {
    return &(stmt->value.statement);
  } else if (stmt->type == BLOCK) {
    return recursive_find_first_statement(block_get_first_child(&(stmt->value.block)));
  }

  fprintf(stderr, "Unknown block type in recursive find");
  return NULL;
}

struct Statement *recursive_find_last_statement(struct SubBlock *stmt) {
  if (stmt->type == STATEMENT) {
    return &(stmt->value.statement);
  } else if (stmt->type == BLOCK) {
    return recursive_find_last_statement(block_get_last_child(&(stmt->value.block)));
  }

  fprintf(stderr, "Unknown block type in recursive find");
  return NULL;
}

void if_stmt(struct Block *block, struct Statement *test,
	     struct SubBlock *then_block, struct SubBlock *else_block) {
  char end_label[64], else_label[64];
  char end_jmp[64], else_jmp[64];
  struct Statement *else_stmt_first,
    *then_stmt_last, *else_stmt_last;

  then_stmt_last = recursive_find_last_statement(then_block);

  if (else_block != NULL) {
    else_stmt_first = recursive_find_first_statement(else_block);
    else_stmt_last = recursive_find_last_statement(else_block);
  }

  // Get a label for just after the last clause
  block_get_unique_name(block, end_label);
  // We'll use this
  sprintf(end_jmp, "jmp %s", end_label);

  if (else_block != NULL) {
    // Get a label for the beginning of the else statement
    block_get_unique_name(block, else_label);
    sprintf(else_jmp, "jz %s", else_label);
  } else {
    strcpy(else_label, end_label);
    sprintf(else_jmp, "jz %s", end_label);
  }

  // Change the labels to be the actual labels now
  strcat(end_label, ":");
  strcat(else_label, ":");

  // If the condition is not met, jump to the 'else'
  statement_pop(test, RAX);
  statement_append_instruction(test, "cmp rax, 0");
  statement_append_instruction(test, else_jmp);

  if (else_block != NULL) {
    statement_append_instruction(then_stmt_last, end_jmp);

    strcpy(else_stmt_first->label, else_label);
    statement_append_instruction(else_stmt_last, end_label);
  } else {
    statement_append_instruction(then_stmt_last, else_label);
  }
}

void while_loop(struct Block *block, struct Statement *test,
		struct SubBlock *stmt) {
  struct Statement *last_stmt;
  char done_label[64], test_label[64],
    done_jmp[64], test_jmp[64];

  block_get_unique_name(block, test_label);
  block_get_unique_name(block, done_label);

  // We want to do the whole comparison every time
  sprintf(test->label, "%s:", test_label);

  sprintf(test_jmp, "jmp %s", test_label);
  sprintf(done_jmp, "jz %s", done_label);

  strcat(test_label, ":");
  strcat(done_label, ":");

  last_stmt = recursive_find_last_statement(stmt);

  statement_pop(test, RAX);
  statement_append_instruction(test, "cmp rax, 0");
  statement_append_instruction(test, done_jmp);

  statement_append_instruction(last_stmt, test_jmp);
  statement_append_instruction(last_stmt, done_label);
}

void oper_bool_or(enum yytokentype a, enum yytokentype b) {
  statement_pop(cur_stmt, RAX);
  statement_pop(cur_stmt, RDX);

  statement_append_instruction(cur_stmt, "add rax, rdx");
  // Default to true
  statement_append_instruction(cur_stmt, "mov rcx, [bool_const_true]");

  // Check whether rax or rdx is zero.
  statement_append_instruction(cur_stmt, "or rax, rdx");

  // If it's zero, then change the result to false
  statement_append_instruction(cur_stmt, "cmovz rcx, QWORD [bool_const_false]");

  statement_push(cur_stmt, RCX);
}

void oper_bool_and(enum yytokentype a, enum yytokentype b)  {
  statement_pop(cur_stmt, RAX);
  statement_pop(cur_stmt, RDX);

  // Default to false
  statement_append_instruction(cur_stmt, "mov rcx, [bool_const_false]");

  // Check whether rax*rdx is zero.
  // What a convenient instruction...
  statement_append_instruction(cur_stmt, "test rax, rdx");

  // If it's not zero, then change the result to true
  statement_append_instruction(cur_stmt, "cmovnz rcx, QWORD [bool_const_true]");

  statement_push(cur_stmt, RCX);
}

void oper_bool_xor(enum yytokentype a, enum yytokentype b)  {
  statement_pop(cur_stmt, RAX);
  statement_pop(cur_stmt, RDX);

  // We need to convert these to actually be one or zero
  // Otherwise, a truthy value xor a truthy value will be
  // true, even though 1 xor 1 is false.

  // Basically, compare to rax to 0. If it is, store 0 in rcx
  // Otherwise, store 1 in rcx. Then replace rax with rcx.
  statement_append_instruction(cur_stmt, "mov rcx, QWORD [bool_const_true]");
  statement_append_instruction(cur_stmt, "cmp rax, QWORD [bool_const_false]");
  statement_append_instruction(cur_stmt, "cmovz rcx, QWORD [bool_const_false]");
  statement_append_instruction(cur_stmt, "mov rax, rcx");

  // Do the same for rdx
  statement_append_instruction(cur_stmt, "mov rcx, QWORD [bool_const_true]");
  statement_append_instruction(cur_stmt, "cmp rdx, QWORD [bool_const_false]");
  statement_append_instruction(cur_stmt, "cmovz rcx, QWORD [bool_const_false]");
  statement_append_instruction(cur_stmt, "mov rdx, rcx");

  // Now we can just xor them
  statement_append_instruction(cur_stmt, "mov rcx, QWORD [bool_const_true]");
  statement_append_instruction(cur_stmt, "xor rax, rdx");
  statement_append_instruction(cur_stmt, "cmovz rcx, QWORD [bool_const_false]");

  statement_push(cur_stmt, RCX);
}

void oper_bool_eq(enum yytokentype a, enum yytokentype b)  {
  statement_append_instruction(cur_stmt, "mov rcx, QWORD [bool_const_false]");
  cmp_bools(a, b);
  statement_append_instruction(cur_stmt, "cmove rcx, QWORD [bool_const_true]");
  statement_push(cur_stmt, RCX);
}

void oper_bool_neq(enum yytokentype a, enum yytokentype b)  {
  statement_append_instruction(cur_stmt, "mov rcx, QWORD [bool_const_true]");
  cmp_bools(a, b);
  statement_append_instruction(cur_stmt, "cmove rcx, QWORD [bool_const_false]");
  statement_push(cur_stmt, RCX);
}

void comparison(enum yytokentype a, enum yytokentype b,
		const char *cc_int, const char *cc_float) {
  char tmp[64];
  type_check(a,b);

  statement_append_instruction(cur_stmt, "mov rcx, QWORD [bool_const_false]");
  switch (a) {
  case INTTYPE:
  case BOOLTYPE:
    cmp_bools(a, b);
    sprintf(tmp, "cmov%s rcx, QWORD [bool_const_true]", cc_int);
    statement_append_instruction(cur_stmt, tmp);
    statement_push(cur_stmt, RCX);
    break;

  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");
    statement_pop(cur_stmt, RAX);
    statement_append_instruction(cur_stmt, "fld QWORD [rsp]");

    statement_stack_align(cur_stmt);
    statement_append_instruction(cur_stmt, "fcomip st1");
    // stack reset might affect rflags? not taking any chances
    sprintf(tmp, "cmov%s rcx, QWORD [bool_const_true]", cc_float);
    statement_append_instruction(cur_stmt, tmp);
    statement_append_instruction(cur_stmt, "fstp st0 ;clear off fp stack");
    statement_stack_reset(cur_stmt);

    statement_append_instruction(cur_stmt, "mov [rsp], rcx");
    break;
  default:
    statement_append_instruction(cur_stmt, "; UNKNOWN TYPE IN COMPARISON");
    break;
  }
}

void oper_bool_lt(enum yytokentype a, enum yytokentype b)  {
  comparison(a, b, "l", "b");
}

void oper_bool_le(enum yytokentype a, enum yytokentype b)  {
  comparison(a, b, "le", "be");
}

void oper_bool_gt(enum yytokentype a, enum yytokentype b)  {
  comparison(a, b, "g", "a");
}

void oper_bool_ge(enum yytokentype a, enum yytokentype b)  {
  comparison(a, b, "ge", "ae");
}

void oper_bool_not(enum yytokentype a)  {
  statement_pop(cur_stmt, RAX);
  statement_append_instruction(cur_stmt, "mov rdx, [bool_const_false]");
  statement_append_instruction(cur_stmt, "cmp rax, 0");
  statement_append_instruction(cur_stmt, "cmovz rdx, [bool_const_true]");
  statement_push(cur_stmt, RDX);
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
