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
 void do_declare(const char *name, enum yytokentype type);
 void do_array_declare(const char *name, enum yytokentype type, long size);
 void if_stmt(struct Block*, struct Statement*,
	      struct SubBlock*, struct SubBlock*);
 void while_loop(struct Block*, struct Statement*, struct SubBlock*, char*, char*);
 void func_def(struct Block*, const char*, struct Statement *dummy_stmt,
	       struct SubBlock*);

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

 long type_promote(enum yytokentype, enum yytokentype);
 enum yytokentype type_check(enum yytokentype, enum yytokentype);
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
%token RETURN
%token BREAK
%token CONTINUE
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
%type <longval> func_call
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
| multi_expr { /*cur_stmt = block_add_statement(cur_scope);*/ } expr {
  statement_call_arg_pop(cur_stmt, $3 == FLOATTYPE);
} ','
;

arg_list:
'(' multi_expr ')'
| '(' VOID ')'
;

any_type:
INTTYPE { $$ = INTTYPE; } | FLOATTYPE { $$ = FLOATTYPE; } | BOOLTYPE { $$ = BOOLTYPE; } | STRINGTYPE { $$ = STRINGTYPE; } | VOID { $$ = VOID; };

param: any_type ID {
  statement_add_parameter(cur_stmt, $2, $1);
};

multi_param:
%empty
| multi_param param ',';

param_list:
'(' multi_param ')'
| '(' VOID ')'
| '(' ')';

func_decl: FUNCDEF any_type ID {
  struct SymbolType st;
  struct StorageLocation sl;
  struct Function *func;
  if (block_resolve_symbol(cur_scope, $3) != NULL) {
    fprintf(stderr, "Symbol %s:\n", $3);
    yyerror("Double declaration invalid");
  }

  st.type = FUNCTION;

  sl.type = REGISTER; // This isn't really true but eh...

  func = block_add_symbol(cur_scope, $3, st, sl)->type.value.function;
  func->return_type = $2;
  func->name = strdup($3);

  cur_scope = block_add_child(cur_scope);
  block_set_function(cur_scope, func);
} param_list {
  cur_stmt = block_add_statement(cur_scope); // append an extra statement so we can add labels and stuff
  statement_append_instruction(cur_stmt, ";; this is a dummy statement");
} stmt {
  struct SubBlock *last_child = block_get_last_child(cur_scope);
  func_def(cur_scope, $3, &(subblock_get_prev(last_child)->value.statement), last_child);

  cur_scope = cur_scope->parent;
};

stmt:
block
| if_else_stmt
| while_loop
| { cur_stmt = block_add_statement(cur_scope); } return_stmt ';'
| { cur_stmt = block_add_statement(cur_scope); } break_stmt ';'
| { cur_stmt = block_add_statement(cur_scope); } continue_stmt ';'
| { cur_stmt = block_add_statement(cur_scope); } print_stmt ';'
| { cur_stmt = block_add_statement(cur_scope); } declare ';'
| { cur_stmt = block_add_statement(cur_scope); } func_decl
| { cur_stmt = block_add_statement(cur_scope); } expr ';'
| NOP { cur_stmt = block_add_statement(cur_scope); } ';'
;

block:
'{' { cur_scope = block_add_child(cur_scope); }
multi_stmt { cur_scope = cur_scope->parent; } '}'
;

return_stmt:
RETURN expr {
  char ret_stmt[64];
  if (cur_scope->containing_function == NULL) {
    yyerror("Invalid return statement outside function definition.");
  } else {
    if (cur_scope->containing_function->return_type == VOID) {
      yyerror("Invalid return value in void function");
    }

    if ($2 != cur_scope->containing_function->return_type) {
      yyerror("Function's return type does not match type of expression in return statement");
    }

    if (cur_scope->containing_function->return_type == FLOATTYPE) {
      statement_append_instruction(cur_stmt, "movq xmm0, QWORD [rsp]");
    }

    sprintf(ret_stmt, "jmp %s__ret", cur_scope->containing_function->name);
    statement_append_instruction(cur_stmt, "pop rax");
    statement_append_instruction(cur_stmt, ret_stmt);
  }
}
| RETURN {
  char ret_stmt[64];
  if (cur_scope->containing_function != NULL) {
    sprintf(ret_stmt, "jmp %s__ret", cur_scope->containing_function->name);
    statement_append_instruction(cur_stmt, ret_stmt);
  } else {
    yyerror("Invalid return statement outside function definition.");
  }
};

break_stmt: BREAK {
  char break_jmp[64];
  if (cur_scope->containing_loop != NULL) {
    sprintf(break_jmp, "jmp %s", cur_scope->containing_loop->end_label);
    statement_append_instruction(cur_stmt, break_jmp);
  } else {
    fprintf(stderr, "scope is %p\n", cur_scope);
    yyerror("Invalid break statement outside of loop.");
  }
};

continue_stmt: CONTINUE {
  char cont_jmp[64];
  if (cur_scope->containing_loop != NULL) {
    sprintf(cont_jmp, "jmp %s", cur_scope->containing_loop->test_label);
    statement_append_instruction(cur_stmt, cont_jmp);
  } else {
    yyerror("Invalid continue statement outside of loop.");
  }
};

while_loop:
{
  // Add a new statement for the test-expression
  cur_scope = block_add_child(cur_scope);
  cur_stmt = block_add_statement(cur_scope);

  cur_scope->containing_loop = malloc(sizeof(struct WhileLoop));
  block_get_unique_name(cur_scope, cur_scope->containing_loop->test_label);
  block_get_unique_name(cur_scope, cur_scope->containing_loop->end_label);
} WHILE '(' expr ')' stmt {
  struct SubBlock *last_child = block_get_last_child(cur_scope);
  while_loop(cur_scope, &(subblock_get_prev(last_child)->value.statement),
	     last_child, cur_scope->containing_loop->test_label,
	     cur_scope->containing_loop->end_label);
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
  statement_pop(cur_stmt, R12);
  statement_push(cur_stmt, RSI);
  statement_push(cur_stmt, RDI);
  switch ($2) {
  case INTTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, R12");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_decimal_nl");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case FLOATTYPE:
    statement_append_instruction(cur_stmt, "movq xmm0, QWORD R12");
    statement_append_instruction(cur_stmt, "mov al, 1");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_float_nl");
    break;
  case STRINGTYPE:
    statement_append_instruction(cur_stmt, "mov rsi, QWORD R12");
    statement_append_instruction(cur_stmt, "mov rdi, fmt_string_nl");
    statement_append_instruction(cur_stmt, "mov al, 0");
    break;
  case BOOLTYPE:
    statement_append_instruction(cur_stmt, "mov rdi, bool_str_true_nl");
    statement_append_instruction(cur_stmt, "mov rax, bool_str_false_nl");
    statement_append_instruction(cur_stmt, "cmp QWORD R12, QWORD 0");
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
  statement_pop(cur_stmt, RDI);
  statement_pop(cur_stmt, RSI);
}
| PRINT expr {
  statement_pop(cur_stmt, R12);
  statement_push(cur_stmt, RSI);
  statement_push(cur_stmt, RDI);
  statement_call_setup(cur_stmt);
  switch ($2) {
  case INTTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "fmt_decimal");
    statement_call_arg_hacky(cur_stmt, 0, "QWORD R12");
    break;
  case FLOATTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "fmt_float");
    statement_call_arg_hacky(cur_stmt, 1, "QWORD R12");
    break;
  case STRINGTYPE:
    statement_call_arg_hacky(cur_stmt, 0, "fmt_string");
    statement_call_arg_hacky(cur_stmt, 0, "QWORD R12");
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
  statement_pop(cur_stmt, RDI);
  statement_pop(cur_stmt, RSI);
}
;

declare:
INTTYPE ID {
  do_declare($2, INTTYPE);
}
| FLOATTYPE ID {
  do_declare($2, FLOATTYPE);
}
| BOOLTYPE ID {
  do_declare($2, BOOLTYPE);
}
| INTTYPE ID '[' INTEGER ']' {
  do_array_declare($2, INTTYPE, $4);
}
| FLOATTYPE ID '[' INTEGER ']' {
  do_array_declare($2, FLOATTYPE, $4);
}
| BOOLTYPE ID '[' INTEGER ']' {
  do_array_declare($2, BOOLTYPE, $4);
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
	yyerror("Incompatible types in assignment");
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
| ID '[' expr ']' '=' expr {
  // integer assignment
  char deref[64];
  char inst[80];
  struct Symbol *array = block_resolve_symbol(cur_scope, $1);

  if ($3 != INTTYPE) {
    yyerror("Array index is not integer.");
  } else {
    array = block_resolve_symbol(cur_scope, $1);

    if (array == NULL) {
      yyerror("Unknown identifier");
    } else {
      if (array->type.type != ARRAY) {
	yyerror("Cannot index non-array expression");
      } else {
	if (array->type.value.primitive != $6) {
	  yyerror("Incomaptible types in assignment");
	} else {
	  statement_pop(cur_stmt, RAX);
	  statement_pop(cur_stmt, RDX);
	  symbol_get_array_reference(array, deref, RDX);
	  sprintf(inst, "mov %s, rax", deref);
	  statement_append_instruction(cur_stmt, inst);
	  $$ = $6;
	}
      }
    }
  }
}
;

func_call:
'.' ID {
  char ref[64];
  struct Symbol *target = block_resolve_symbol(cur_scope, $2);
  cur_stmt = block_add_statement(cur_scope);

  printf(";; Calling function %s\n", $2);

  if (target == NULL) {
    yyerror("Unknown identifier");
  } else {
    if (target->type.type != FUNCTION) {
      yyerror("Incompatible types in function call");
    } else {
      symbol_get_reference(target, ref);
      statement_call_setup(cur_stmt);
      // TODO move this into an expression
    }
  }
}
arg_list {
  struct Function *func = block_resolve_symbol(cur_scope, $2)->type.value.function;
  statement_call_finish(cur_stmt, $2);
  if (func->return_type == FLOATTYPE) {
    statement_append_instruction(cur_stmt, "movq QWORD [rsp], xmm0");
  }
  $$ = func->return_type;
};

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
| ID '[' expr ']' {
  struct Symbol *array;
  char deref[64];
  char inst[128];
  if ($3 != INTTYPE) {
    yyerror("Array index is not integer.");
  } else {
    array = block_resolve_symbol(cur_scope, $1);

    if (array == NULL) {
      yyerror("Unknown identifier");
    } else {
      if (array->type.type != ARRAY) {
	yyerror("Cannot index non-array expression");
      } else {
	statement_pop(cur_stmt, RAX);
	symbol_get_array_reference(array, deref, RAX);
	sprintf(inst, "mov rax, %s", deref);
	statement_append_instruction(cur_stmt, inst);
	statement_push(cur_stmt, RAX);
	$$ = array->type.value.primitive;
      }
    }
  }
}
| func_call
| expr BOOL_OR expr            { $$ = BOOLTYPE; oper_bool_or($1, $3); }
| expr BOOL_AND expr           { $$ = BOOLTYPE; oper_bool_and($1, $3); }
| expr BOOL_XOR expr           { $$ = BOOLTYPE; oper_bool_xor($1, $3); }
| expr BOOL_EQUAL expr         { $$ = BOOLTYPE; oper_bool_eq($1, $3); }
| expr BOOL_NOT_EQUAL expr     { $$ = BOOLTYPE; oper_bool_neq($1, $3); }
| expr '<' expr                { $$ = BOOLTYPE; oper_bool_lt($1, $3); }
| expr BOOL_LESS_EQUAL expr    { $$ = BOOLTYPE; oper_bool_le($1, $3); }
| expr '>' expr                { $$ = BOOLTYPE; oper_bool_gt($1, $3); }
| expr BOOL_GREATER_EQUAL expr { $$ = BOOLTYPE; oper_bool_ge($1, $3); }

| expr '+' expr   { $$ = type_check($1, $3); oper_add($$); }
| expr '-' expr   { $$ = type_check($1, $3); oper_sub($$); }
| expr '*' expr   { $$ = type_check($1, $3); oper_mul($$); }
| expr '/' expr   { $$ = type_check($1, $3); oper_div($$); }
| expr '%' expr   { $$ = type_check($1, $3); oper_mod($$); }
| '-' expr        { $$ = $2; oper_neg($$); }
| '!' expr        { $$ = BOOLTYPE; oper_bool_not($2); }
| expr POW expr   { $$ = type_check($1, $3); oper_pow($$); }
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
  symbol = block_add_symbol_initialized(&global_scope, tmp2, FLOATTYPE, tmp);

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

void do_declare(const char *name, enum yytokentype type) {
  struct SymbolType st;
  struct StorageLocation sl;

  if (block_resolve_symbol(cur_scope, name) != NULL) {
    fprintf(stderr, "Symbol %s:\n", name);
    yyerror("Double declaration invalid");
  }

  st.type = PRIMITIVE;
  st.value.primitive = type;

  printf(";; declaring %s\n", name);

  sl.type = cur_scope->containing_function == NULL ? LABEL : LOCAL;

  block_add_symbol(cur_scope, name, st, sl);
}

void do_array_declare(const char *name, enum yytokentype type, long size) {
  struct SymbolType st;
  struct StorageLocation sl;

  if (block_resolve_symbol(cur_scope, name) != NULL) {
    fprintf(stderr, "Symbol: %s\n", name);
    yyerror("Double declaration invalid");
  }

  st.type = ARRAY;
  st.value.primitive = type;

  sl.type = cur_scope->containing_function == NULL ? LABEL : LOCAL;

  block_add_symbol_array(cur_scope, name, st, sl, size);
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
		struct SubBlock *stmt, char *test_label, char *done_label) {
  struct Statement *last_stmt;
  char done_jmp[64], test_jmp[64],
    test_label_inst[64], done_label_inst[64];


  // We want to do the whole comparison every time
  sprintf(test->label, "%s:", test_label);

  sprintf(test_jmp, "jmp %s", test_label);
  sprintf(done_jmp, "jz %s", done_label);

  sprintf(test_label_inst, "%s:", test_label);
  sprintf(done_label_inst, "%s:", done_label);

  last_stmt = recursive_find_last_statement(stmt);

  statement_pop(test, RAX);
  statement_append_instruction(test, "cmp rax, 0");
  statement_append_instruction(test, done_jmp);

  statement_append_instruction(last_stmt, test_jmp);
  statement_append_instruction(last_stmt, done_label_inst);
}

void func_def(struct Block *block, const char *name, struct Statement *dummy_stmt, struct SubBlock *body) {
  struct Statement *last_stmt, *first_stmt;
  char start_label[64], end_label[64],
    ret_label[64], skip_jmp[64];

  block_get_unique_name(block, end_label);

  sprintf(start_label, "%s:", name);
  sprintf(skip_jmp, "jmp %s", end_label);
  sprintf(ret_label, "%s__ret:", name);

  strcat(end_label, ":");

  first_stmt = recursive_find_first_statement(body);
  last_stmt = recursive_find_last_statement(body);

  // this is a dummy statement so it's ok to append
  statement_append_instruction(dummy_stmt, skip_jmp);
  statement_append_instruction(dummy_stmt, start_label);
  //statement_push(first_stmt, RBP);
  // I don't think we need to track push/pop within functions... yet...
  statement_append_instruction(dummy_stmt, "push rbp");
  statement_append_instruction(dummy_stmt, "mov rbp, rsp");
  statement_append_instruction(last_stmt, "mov rax, [rsp]");
  statement_append_instruction(last_stmt, ret_label);
  statement_append_instruction(last_stmt, "mov rsp, rbp");
  statement_append_instruction(last_stmt, "pop rbp");
  statement_append_instruction(last_stmt, "ret");
  statement_append_instruction(last_stmt, end_label);
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

long type_promote(enum yytokentype a, enum yytokentype b) {
  char inst[32];
  // b is on top of stack
  // a is next

  // no need to convert anything
  if (a == b) {
    return 1;
  }

  if (a == FLOATTYPE && (b == INTTYPE || b == BOOLTYPE)) {
    // we need to convert B to an int
    statement_append_instruction(cur_stmt, "fild QWORD [rsp]");
    statement_stack_align(cur_stmt);
    sprintf(inst, "fstp QWORD [rsp+%ld]", cur_stmt->realignment);
    statement_append_instruction(cur_stmt, inst);
    statement_stack_reset(cur_stmt);
    return 1;
  }
  if (b == FLOATTYPE && (a == INTTYPE || a == BOOLTYPE)) {
    // we need to convert A to an int
    statement_append_instruction(cur_stmt, "fild QWORD [rsp+8]");
    statement_stack_align(cur_stmt);
    sprintf(inst, "fstp QWORD [rsp+%ld]", cur_stmt->realignment+8);
    statement_append_instruction(cur_stmt, inst);
    statement_stack_reset(cur_stmt);
    return 2;
  }

  return 0;
}

enum yytokentype type_check(enum yytokentype a, enum yytokentype b) {
  long res = type_promote(a, b);
  if (!res) {
    fprintf(stderr, "%d and %d: ", a, b);
    yyerror("Incompatible Types in expression");
    return a;
  } else if (res == 1) {
    return a;
  } else if (res == 2) {
    return b;
  } else {
    return a;
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
