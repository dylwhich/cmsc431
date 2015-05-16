#include "program.h"
#include "uthash.h"

#include <malloc.h>
#include <stdbool.h>
#include <string.h>
#include <alloca.h>

static enum Register ARG_REGISTERS_INT[] = {RDI, RSI, RDX, RCX, R8, R9};
static enum Register ARG_REGISTERS_FLOAT[] = {XMM0, XMM1, XMM2, XMM3,
					      XMM4, XMM5, XMM6, XMM7};

void block_init(struct Block *this, const char *name, struct Block *parent) {
  enum Register i;
  this->symbol_table = NULL;

  this->name = (char*) malloc(sizeof(char) * (strlen(name) + 1));
  strcpy(this->name, name);
  this->name[strlen(name)] = '\0';

  this->parent = parent;

  this->len_children = 4;
  this->num_children = 0;
  this->children = malloc(this->len_children * sizeof(struct SubBlock));

  this->prev = NULL;
  this->next = NULL;

  // Keep the global data in sync with all the blocks
  if (block_is_global(this)) {
    this->global_data = malloc(sizeof(struct GlobalData));
    this->global_data->next_bss_offset = 0;
    this->global_data->bss_label = malloc(8 * sizeof(char));
    strcpy(this->global_data->bss_label, "globals");

    this->global_data->next_data_offset = 0;
    this->global_data->data_label = malloc(12 * sizeof(char));
    strcpy(this->global_data->data_label, "initglobals");

    this->global_data->stack_size = 0;

    this->global_data->nonce = 0;
  } else {
    this->global_data = parent->global_data;
  }

  for (i = RAX; i <= XMM7; i++) {
    this->registers[i] = 0;
  }

  this->next_local = 0;

  this->containing_function = NULL;
};

void block_write(struct Block *this, FILE *out) {
  block_write_head(this, out);
  block_write_body(this, out);
  block_write_tail(this, out);
}

void block_write_head(struct Block *this, FILE *out) {
  struct Symbol *symbol;
  struct SubBlock *child;
  fprintf(out, "; block_head: %s\n", this->name);

  if (block_is_global(this)) {
    // BEGIN HACK
    // TODO make something for declaring constant globals here
    fprintf(out, "extern printf\n");
    fprintf(out, "extern scanf\n");
    fprintf(out, "extern pow\n");
    fprintf(out, "extern fmod\n\n");
    fprintf(out, "SECTION .data\n");
    fprintf(out, "fmt_decimal_nl:\n    db \"%%ld\", 10, 0\n\n");
    fprintf(out, "fmt_decimal:\n    db \"%%ld\", 0\n\n");
    fprintf(out, "fmt_float_nl:\n    db \"%%.4lf\", 10, 0\n\n");
    fprintf(out, "fmt_float:\n    db \"%%.4lf\", 0\n\n");
    fprintf(out, "fmt_string_nl:\n    db \"%%s\", 10, 0\n\n");
    fprintf(out, "fmt_string:\n    db \"%%s\", 0\n\n");
    fprintf(out, "fmt_input_int:\n    db \"%%ld\", 0\n\n");
    fprintf(out, "fmt_input_float:\n    db \"%%lf\", 0\n\n");
    fprintf(out, "bool_str_true:\n    db \"true\", 0\n\n");
    fprintf(out, "bool_str_false:\n    db \"false\", 0\n\n");
    fprintf(out, "bool_str_true_nl:\n    db \"true\", 10, 0\n\n");
    fprintf(out, "bool_str_false_nl:\n    db \"false\", 10, 0\n\n");
    fprintf(out, "bool_const_true:\n    dq 1\n\n");
    fprintf(out, "bool_const_false:\n    dq 0\n\n");
    // END HACK
    fprintf(out, "%s: \n", this->global_data->data_label);

    for (symbol=this->symbol_table; symbol != NULL; symbol = symbol->hh.next) {
      if (symbol->location.type == INITIALIZED) {
	symbol_write_declaration(symbol, out);
      }
    }
    fprintf(out, "SECTION .bss\n");
    fprintf(out, "%s: \n", this->global_data->bss_label);
  }

  for (symbol=this->symbol_table; symbol != NULL; symbol = symbol->hh.next) {
    if (symbol->location.type != INITIALIZED &&
	symbol->location.type != LOCAL) {
      symbol_write_declaration(symbol, out);
    }
  }

  for (child = this->children; child < (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_head(&(child->value.block), out);
    }
  }
}

void block_write_body(struct Block *this, FILE *out) {
  struct SubBlock *child;
  struct Symbol *symbol;

  fprintf(out, "; block_body: %s\n", this->name);

  if (this->parent != NULL) {
    fprintf(out, ";;; (n)th child block of parent %s\n", this->parent->name);
  }

  if (block_is_global(this)) {
    fprintf(out, "    SECTION .text:\n");
    fprintf(out, "    global main\n");
    fprintf(out,
	    "intpow:\n"
	    "    push rbp\n"
	    "    mov rbp, rsp\n\n"

	    "    mov rcx, rdi\n"
	    "    mov rax, QWORD 1\n\n"

	    "    cmp rcx, 0\n" // skip the loop for zero-power
	    "    jz .end\n\n"

	    "    cmp rcx, 0\n" // check for invalid (for integers) input
	    "    jl .invalid\n\n"

	    "    jmp .loop\n"
	    "    .invalid:\n"
	    "    mov rax, 1\n"
	    "    jmp .end\n\n"

	    "    .loop:\n"
	    "    imul rax, rsi\n"
	    "    loop .loop\n"
	    "    .end:\n\n"

	    "    mov rsp, rbp\n"
	    "    pop rbp\n"
	    "    ret\n");
    // we would do what asm_func_return_regval does, but it's
    // redundant so it doesn't do anything anyway
    fprintf(out,
	    "main:\n"
	    "push rbp\n"
	    "mov rbp, rsp\n");
  } else fprintf(out, "%s:\n", this->name);

  for (symbol = this->symbol_table; symbol != NULL; symbol = symbol->hh.next) {
    if (symbol->location.type == LOCAL) {
      symbol_write_declaration(symbol, out);
    }
  }

  for (child = this->children; child < (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_body(&(child->value.block), out);
    } else if (child->type == STATEMENT) {
      statement_write(&child->value.statement, out);
    }
  }

  if (this->next_local != 0) {
    fprintf(out, "sub rsp, %ld", this->next_local);
  }

  fprintf(out, ";end block_body %s\n", this->name);
  if (this->parent != NULL) {
    fprintf(out, ";return to parent %s\n", this->parent->name);
  }
}

void block_write_tail(struct Block *this, FILE *out) {
  struct SubBlock *child;
  fprintf(out, "; block_tail: %s\n", this->name);
  for (child = this->children; child < (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_tail(&(child->value.block), out);
    }
  }

  if (block_is_global(this)) {
    // TODO is this actually right?
    // No, it should be part of wrapping a block in a function!
    fprintf(out, "mov rsp, rbp\n");
    fprintf(out, "pop rbp\n");
    fprintf(out, "ret\n");
  }
}

struct Block *block_add_child(struct Block *this) {
  // TODO don't hardcode this, somehow?
  char *tmp = (char*) alloca(sizeof(char) * 11);
  sprintf(tmp, "%03ld", this->num_children);
  return block_add_named_child(this, tmp);
}

struct Block *block_add_named_child(struct Block *this, const char *name) {
  char *tmp = (char*) alloca(sizeof(char) * (strlen(name) + strlen(this->name) + 2));
  sprintf(tmp, "%s_%s", this->name, name);

  while (this->num_children >= this->len_children) {
    __block_grow_children(this);
  }

  this->children[this->num_children].type = BLOCK;
  block_init(&(this->children[this->num_children].value.block), tmp, this);
  this->children[this->num_children].value.block.containing_function = this->containing_function;

  if (this->num_children != 0) {
    subblock_set_prev(&(this->children[this->num_children]), &(this->children[this->num_children-1]));
    subblock_set_next(&(this->children[this->num_children-1]), &(this->children[this->num_children]));
  }

  return &(this->children[this->num_children++].value.block);
}

struct Statement *block_add_statement(struct Block *this) {
  while (this->num_children >= this->len_children) {
    __block_grow_children(this);
  }

  this->children[this->num_children].type = STATEMENT;
  statement_init(&(this->children[this->num_children].value.statement), this);

  if (this->num_children != 0) {
    subblock_set_prev(&(this->children[this->num_children]), &(this->children[this->num_children-1]));
    subblock_set_next(&(this->children[this->num_children-1]), &(this->children[this->num_children]));
  }

  return &(this->children[this->num_children++].value.statement);
}

void block_get_unique_name(struct Block *this, char *out) {
  sprintf(out, "l0_%lx", this->global_data->nonce++);
}

struct Symbol *block_add_symbol(struct Block *this, const char *name, struct SymbolType type, struct StorageLocation location) {
  struct Symbol *symbol = (struct Symbol*)malloc(sizeof(struct Symbol));

  // TODO: don't use a constant size for the symbol table...
  symbol->type = type;

  if (symbol->location.type == LABEL) {
    symbol_init(symbol, type, this->global_data->next_bss_offset, 8, this, name);
    symbol->location = location;
    this->global_data->next_bss_offset += 8;
  } else if (symbol->location.type == LOCAL) {
    printf(";; adding symbol %s, current next_local is %ld\n", name, this->next_local);
    symbol_init(symbol, type, this->next_local, 8, this, name);
    this->next_local += 8;
    //symbol->location = location;
    symbol->location.type = location.type;
  }

  HASH_ADD_STR(this->symbol_table, label, symbol);
  return symbol;
}

struct Symbol *block_add_symbol_initialized(struct Block *this, const char *name, enum yytokentype type, const char *initial_value) {
  struct Symbol *symbol = (struct Symbol*)malloc(sizeof(struct Symbol));
  struct SymbolType st;
  st.type = PRIMITIVE;
  st.value.primitive = type;

  // TODO: don't hardcode
  // TODO: Support non-global initialization

  printf(";; adding INITIALIZED symbol %s\n", name);
  symbol_init(symbol, st, this->global_data->next_data_offset, 8, this, name);
  this->global_data->next_data_offset += 8;

  symbol->location.type = INITIALIZED;

  strncpy(symbol->initval, initial_value, sizeof(symbol->initval));

  HASH_ADD_STR(this->symbol_table, label, symbol);
  return symbol;
};

struct Symbol *block_resolve_symbol(struct Block *this, const char *name) {
  struct Symbol *result = NULL;
  HASH_FIND_STR(this->symbol_table, name, result);
  if (result != NULL) {
    return result;
  } else if (!block_is_global(this)) {
    return block_resolve_symbol(this->parent, name);
  } else {
    return NULL;
  }
}

bool block_is_global(struct Block *this) {
  return this->parent == NULL;
}

struct SubBlock *block_get_first_child(struct Block *this) {
  if (this->num_children > 0) {
    return this->children;
  } else {
    return NULL;
  }
}

struct SubBlock *block_get_last_child(struct Block *this) {
  if (this->num_children > 0) {
    return &(this->children[this->num_children-1]);
  }
  return NULL;
}

enum Register block_register_acquire_int(struct Block *this) {
  enum Register r;
  for (r = RAX; r <= R15; r++) {
    if (!this->registers[r]) {
      this->registers[r] = 1;
      return r;
    }
  }

  return -1;
}

enum Register block_register_acquire_float(struct Block *this) {
  enum Register r;
  for (r = XMM0; r <= XMM7; r++) {
    if (!this->registers[r]) {
      this->registers[r] = 1;
      return r;
    }
  }

  return -1;
}

long block_register_used(struct Block *this, enum Register reg) {
  return this->registers[reg];
}

void block_register_release(struct Block *this, enum Register reg) {
  this->registers[reg] = 0;
}

void block_destroy(struct Block *this) {
  struct SubBlock *child;
  struct Symbol *symbol, *tmp_symbol;
  free(this->name);
  this->name = NULL;

  for (child = this->children; child < (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_destroy(&(child->value.block));
    } else if (child->type == STATEMENT) {
      statement_destroy(&(child->value.statement));
    }
  }

  HASH_ITER(hh, this->symbol_table, symbol, tmp_symbol) {
    HASH_DEL(this->symbol_table, symbol);

    if (symbol->type.type == FUNCTION) {
      // TODO Move this to a symbol_destroy
      free(symbol->type.value.function);
    }
    free(symbol);
  }

  free(this->symbol_table);

  free(this->children);
  this->children = NULL;

  if (block_is_global(this)) {
    free(this->global_data->bss_label);
    free(this->global_data->data_label);
    free(this->global_data);
    this->global_data = NULL;
  } else {
    this->global_data = NULL;
  }
}

void __block_grow_children(struct Block *this) {
  struct SubBlock *tmp;
  tmp = (struct SubBlock*)realloc(this->children, this->len_children * 2 * sizeof(struct SubBlock));
  if (tmp != NULL) {
    this->children = tmp;
    this->len_children *= 2;
  } else {
    exit(1);
  }
}

void subblock_set_prev(struct SubBlock *this, struct SubBlock *prev) {
  if (this->type == BLOCK) {
    this->value.block.prev = prev;
  } else if (this->type == STATEMENT) {
    this->value.statement.prev = prev;
  }
}

struct SubBlock *subblock_get_prev(struct SubBlock *this) {
  if (this->type == BLOCK) {
    return this->value.block.prev;
  } else {
    return this->value.statement.prev;
  }
}

void subblock_set_next(struct SubBlock *this, struct SubBlock *next) {
  if (this->type == BLOCK) {
    this->value.block.next = next;
  } else if (this->type == STATEMENT) {
    this->value.statement.next = next;
  }
}

void statement_init(struct Statement *this, struct Block *parent) {
  char tmp[128];

  // TODO don't hardcode
  this->buffer_size = 512;
  this->buffer = (char*) calloc(this->buffer_size, sizeof(char));
  this->realignment = 0;
  this->parent = parent;
  this->next = NULL;
  this->prev = NULL;
  this->label[0] = '\0';
  this->call_stack_index = -1;

  sprintf(tmp, ";;; %ldth child stmt of parent %s", parent->num_children, parent->name);
  statement_append_instruction(this, tmp);
}

void statement_append_instruction(struct Statement *this, const char *asm_instruction) {
  size_t actual_len, input_len;
  char *tmp;
  actual_len = strlen(this->buffer);
  input_len = strlen(asm_instruction);
  while (actual_len + input_len + 2 >= this->buffer_size) {
    // the '+2' is to account for a newline we'll insert and the
    // NULL-terminator
    tmp = realloc(this->buffer, this->buffer_size * 2);
    if (tmp != NULL) {
      this->buffer = tmp;
      this->buffer_size *= 2;
    }
  }

  strncpy(this->buffer + actual_len, asm_instruction, input_len);
  this->buffer[actual_len + input_len] = '\n';
  this->buffer[actual_len + input_len + 1] = '\0';
}

void statement_push(struct Statement *this, enum Register regname) {
  char reg[8], inst[64];
  register_get_name(regname, reg);
  sprintf(inst, "push QWORD %s", reg);
  statement_append_instruction(this, inst);
  this->parent->global_data->stack_size += 8;
}

void statement_pop(struct Statement *this, enum Register regname) {
  char reg[8], inst[64];
  //this->parent->registers[regname] = 1;
  register_get_name(regname, reg);
  sprintf(inst, "pop QWORD %s", reg);
  statement_append_instruction(this, inst);
  this->parent->global_data->stack_size -= 8;
}

void statement_grow_stack(struct Statement *this, size_t bytes) {
  char inst[64];

  sprintf(inst, "sub rsp, %zu", bytes);

  statement_append_instruction(this, inst);
  this->parent->global_data->stack_size += bytes;
}

void statement_shrink_stack(struct Statement *this, size_t bytes) {
  char inst[64];

  sprintf(inst, "add rsp, %zu", bytes);

  statement_append_instruction(this, inst);
  this->parent->global_data->stack_size -= bytes;
}

void statement_add_parameter(struct Statement *this, const char *name, enum yytokentype type) {
  struct Block *block = this->parent;
  struct Symbol *symbol;
  enum Register reg;

  struct SymbolType s_type;
  struct StorageLocation s_location;

  s_type.type = PRIMITIVE;
  s_type.value.primitive = type;

  if (type == FLOATTYPE) {
    reg = ARG_REGISTERS_FLOAT[this->float_regs_used[this->call_stack_index]++];
  } else {
    reg = ARG_REGISTERS_INT[this->int_regs_used[this->call_stack_index]++];
  }

  if (reg == (enum Register) -1) {
    // We're out of registers! Whaa
    // won't worry about this now
    s_location.type = PARAM;
    //s_location.value.address =
  } else {
    block->registers[reg] = 1;
    s_location.type = REGISTER;
    s_location.value.regname = reg;
  }

  block_add_symbol(block, name, s_type, s_location);
}

void statement_call_setup(struct Statement *this) {
  enum Register i;
  // stores the current frame's values
  /*for (i = RBX; i <= R15; i++) {
    if (this->parent->registers[i]) {
      statement_push(this, i);
    }
    }*/

  statement_append_instruction(this, "xor rax, rax");
  this->call_stack_index++;
}

void statement_call_arg(struct Statement *this, struct Symbol *arg) {
  char argloc[64];
  symbol_get_reference(arg, argloc);

  if (arg->type.type == PRIMITIVE && arg->type.value.primitive == FLOATTYPE) {
    statement_call_arg_hacky(this, 1, argloc);
  } else {
    statement_call_arg_hacky(this, 0, argloc);
  }
}

void statement_call_arg_hacky(struct Statement *this, long is_float, const char *src) {
  char regname[32], inst[64];
  char *mov_op;
  enum Register used_reg;

  statement_append_instruction(this, "; adding argument");

  if (is_float) {
    statement_append_instruction(this, "add al, 1");
    used_reg = ARG_REGISTERS_FLOAT[this->float_regs_used[this->call_stack_index]++];
    mov_op = "movq";
  } else {
    used_reg = ARG_REGISTERS_INT[this->int_regs_used[this->call_stack_index]++];
    mov_op = "mov";
  }

  if (used_reg == -1) {
    statement_append_instruction(this, ";;;;=== Too many registers used??? register_acquire == -1");
  }

  // Does not account for moving a register to itself...
  statement_append_instruction(this, "; pushing arg");
  //statement_push(this, used_reg);
  register_get_name(used_reg, regname);
  sprintf(inst, "%s %s, %s", mov_op, regname, src);
  statement_append_instruction(this, inst);
}

void statement_call_finish(struct Statement *this, const char *func) {
  char out[128];
  enum Register i;
  long j;

  statement_stack_align(this);

  sprintf(out, "call %s", func);
  statement_append_instruction(this, out);
  //  statement_push(this, RAX); // right thing to do?

  statement_stack_reset(this);

  fprintf(stderr, "call_stack_index is %d\n", this->call_stack_index);
  fprintf(stderr, "Starting j at %d\n", this->int_regs_used[this->call_stack_index] - 1);
  fprintf(stderr, "starting float j at %d\n", this->float_regs_used[this->call_stack_index] - 1);

  for (j = this->int_regs_used[this->call_stack_index]-1; j >= 0; j--) {
    statement_append_instruction(this, "; popping arg");
    //statement_pop(this, ARG_REGISTERS_INT[j]);
  }

  for (j = this->float_regs_used[this->call_stack_index]-1; j >= 0; j--) {
    statement_append_instruction(this, "; popping arg");
    //statement_pop(this, ARG_REGISTERS_FLOAT[j]);
  }

  // stores the current frame's values
  /*for (i = R15; i > RAX; i--) {
    if (this->parent->registers[i]) {
      statement_pop(this, i);
    }
    }*/

  this->call_stack_index--;

  statement_push(this, RAX);
}

void statement_push_int(struct Statement *this, long val) {
  char inst[64];
  sprintf(inst, "push QWORD %ld", val);
  statement_append_instruction(this, inst);
  this->parent->global_data->stack_size += 8;
}

void statement_stack_align(struct Statement *this) {
  char instr[32];
  long alignment = this->parent->global_data->stack_size % STACK_ALIGNMENT;

  if (alignment) {
    sprintf(instr, "add rsp, %ld; REALIGN", alignment);
    statement_append_instruction(this, instr);
    this->parent->global_data->stack_size += alignment;
    this->realignment = alignment;
  }
}

void statement_stack_reset(struct Statement *this) {
  char instr[32];
  if (this->realignment) {
    sprintf(instr, "sub rsp, %ld; DEALIGN", this->realignment);
    statement_append_instruction(this, instr);
    this->parent->global_data->stack_size -= this->realignment;
    this->realignment = 0;
  }
}

void statement_write(struct Statement *this, FILE *out) {
  fprintf(out, "; statement-begin\n");

  if (strlen(this->label)) {
    fprintf(out, "%s\n", this->label);
  }

  fprintf(out, "%s", this->buffer);
  fprintf(out, "; statement-end\n");
}

void statement_destroy(struct Statement *this) {
  free(this->buffer);
  this->buffer = NULL;
}

void register_write_name(enum Register regname, FILE *out) {
  switch(regname) {
  case RAX:
    fprintf(out, "rax");
    break;

  case RBX:
    fprintf(out, "rbx");
    break;

  case RCX:
    fprintf(out, "rcx");
    break;

  case RDX:
    fprintf(out, "rdx");
    break;

  case RSI:
    fprintf(out, "rsi");
    break;

  case RDI:
    fprintf(out, "rdi");
    break;

  case R8:
    fprintf(out, "r8");
    break;

  case R9:
    fprintf(out, "r9");
    break;

  case R10:
    fprintf(out, "r10");
    break;

  case R11:
    fprintf(out, "r11");
    break;

  case R12:
    fprintf(out, "r12");
    break;

  case R13:
    fprintf(out, "r13");
    break;

  case R14:
    fprintf(out, "r14");
    break;

  case R15:
    fprintf(out, "r15");
    break;

  default:
    fprintf(out, "[YOU BROKE SOMETHING]");
    break;
  }
}

void register_get_name(enum Register regname, char *out) {
  switch(regname) {
  case RAX:
    sprintf(out, "rax");
    break;

  case RBX:
    sprintf(out, "rbx");
    break;

  case RCX:
    sprintf(out, "rcx");
    break;

  case RDX:
    sprintf(out, "rdx");
    break;

  case RSI:
    sprintf(out, "rsi");
    break;

  case RDI:
    sprintf(out, "rdi");
    break;

  case R8:
    sprintf(out, "r8");
    break;

  case R9:
    sprintf(out, "r9");
    break;

  case R10:
    sprintf(out, "r10");
    break;

  case R11:
    sprintf(out, "r11");
    break;

  case R12:
    sprintf(out, "r12");
    break;

  case R13:
    sprintf(out, "r13");
    break;

  case R14:
    sprintf(out, "r14");
    break;

  case R15:
    sprintf(out, "r15");
    break;

  default:
    sprintf(out, "[YOU BROKE SOMETHING]");
    break;
  }
}

void symbol_init(struct Symbol *this, struct SymbolType type, long offset,
		 size_t size, struct Block*scope, const char *label) {
  this->type = type;
  this->offset = offset;
  this->size = size;

  this->scope = scope;

  if (this->type.type == FUNCTION) {
    this->type.value.function = malloc(sizeof(struct Function));
  }

  strncpy(this->label, label, SYMBOL_MAX_LENGTH);
  this->label[SYMBOL_MAX_LENGTH-1] = '\0';
}

void string_write_nasm(FILE *out, const char *in) {
  // Skip the beginning quote
  const char *cur = in + 1;
  int in_str = 0;
  int escaping = 0;

  if (*cur == '\\') {
    escaping = 1;
  } else if (*cur < 32 || *cur == 34 || *cur > 126) {
    fprintf(out, "%d, ", *cur);
  } else {
    fprintf(out, "\"%c", *cur);
    in_str = 1;
  }

  cur++;

  while (*cur != '\0') {
    // Ignore the ending quote
    if (*cur == 34 && *(cur+1) == '\0') {
      break;
    }

    if (*cur == '\\') {
      if (escaping) {
	if (in_str)
	  fprintf(out, "\\");

	if (cur != in + 2)
	  fprintf(out, ", ");

	fprintf(out, "92");

	escaping = 0;
      } else {
	escaping = 1;
      }
    } else if (escaping) {
      if (in_str)
	fprintf(out, "\"");

      if (cur != in + 2)
	fprintf(out, ", ");

      switch (*cur) {
      case '0':
	fprintf(out, "0");
	break;
      case '"':
	fprintf(out, "34");
	break;
      case 'b':
	fprintf(out, "8");
	break;
      case 'f':
	fprintf(out, "12");
	break;
      case 'n':
	fprintf(out, "10");
	break;
      case 'r':
	fprintf(out, "13");
	break;
      case 't':
	fprintf(out, "9");
	break;
      case 'v':
	fprintf(out, "11");
	break;
      default:
	fprintf(out, "%d", *cur);
	break;
      }
      escaping = 0;
      in_str = 0;
    } else if (*cur < 32 || *cur == 34 || *cur > 126) {
      if (in_str) {
	fprintf(out, "\", %d", *cur);
      } else {
	fprintf(out, ", %d", *cur);
      }
      in_str = 0;
    } else {
      if (in_str) {
	fprintf(out, "%c", *cur);
      } else {
	fprintf(out, ", \"%c", *cur);
      }
      in_str = 1;
    }
    cur++;
  }
  if (in_str) {
    fprintf(out, "\"");
  }

  fprintf(out, ", 0\n");
}

void symbol_write_declaration(struct Symbol *this, FILE *out) {
  switch (this->location.type) {
  case LABEL:
    fprintf(out, "    resq %ld\n", this->size / 8 ? this->size / 8 : 1);
    break;

  case ADDRESS:
    // Wait, what do I do here???
    fprintf(out, "; You should probably fix symbol_write_declaration\n");
    break;

  case LOCAL:
    fprintf(out, ";;; declaring local\n");
    fprintf(out, "sub rsp, %ld\n", this->size);
    break;

  case REGISTER:
    // I'm pretty sure we don't have to do anything here
    break;

  case PARAM:
    break;

  case INITIALIZED:
    if (this->type.type == PRIMITIVE && this->type.value.primitive == STRINGTYPE) {
      fprintf(out, "    dq ");
      string_write_nasm(out, this->initval);
    } else {
      fprintf(out, "    dq %s\n", this->initval);
    }
    break;

  default:
    fprintf(out, ";;;;;\n;;;;;\n;     ADD SUPPORT FOR THE NEW VARIABLE LOCATION, DOOFUS\n;;;;;\n;;;;;\n");
    break;
  }
}

void symbol_write_reference(struct Symbol *this, FILE *out) {
  // This function should be renamed symbol_write_dereference, and it
  // should just put brackets around the actual
  // symbol_write_reference...
  switch(this->location.type) {
  case LABEL:
    fprintf(out, "qword [%s+%ld]", this->scope->global_data->bss_label, this->offset);
    break;

  case ADDRESS:
    fprintf(out, "qword [%ld]", this->location.value.address);
    break;

  case LOCAL:
    fprintf(out, "qword [rbp-%ld]", this->offset);
    break;

  case REGISTER:
    register_write_name(this->location.value.regname, out);
    break;

  case PARAM:
    fprintf(out, "qword [rbp+%ld]", this->offset);
    break;

  case INITIALIZED:
    fprintf(out, "qword [%s+%ld]", this->scope->global_data->data_label, this->offset);
    break;
  }
}

void symbol_get_reference(struct Symbol *this, char *out) {
  // This function should be renamed symbol_write_dereference, and it
  // should just put brackets around the actual
  // symbol_write_reference...
  switch(this->location.type) {
  case LABEL:
    sprintf(out, "qword [%s+%ld]", this->scope->global_data->bss_label, this->offset);
    break;

  case ADDRESS:
    sprintf(out, "qword [%ld]", this->location.value.address);
    break;

  case LOCAL:
    sprintf(out, "qword [rbp-%ld]", this->offset);
    break;

  case REGISTER:
    register_get_name(this->location.value.regname, out);
    break;

  case PARAM:
    sprintf(out, "qword [rbp+%ld]", this->offset);
    break;

  case INITIALIZED:
    if (this->type.type == PRIMITIVE && this->type.value.primitive == STRINGTYPE) {
      sprintf(out, ";;woooo\n");
      sprintf(out, "[%s+%ld]", this->scope->global_data->data_label, this->offset);
    } else {
      sprintf(out, "qword [%s+%ld]", this->scope->global_data->data_label, this->offset);
    }
    break;
  }
}
