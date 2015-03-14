#include "program.h"
#include "uthash.h"

#include <malloc.h>
#include <stdbool.h>
#include <string.h>
#include <alloca.h>

void block_init(struct Block *this, const char *name, struct Block *parent) {
  this->symbol_table = NULL;

  this->name = (char*) malloc(sizeof(char) * (strlen(name) + 1));
  strcpy(this->name, name);
  this->name[strlen(name)] = '\0';

  this->parent = parent;

  this->len_children = 4;
  this->num_children = 0;
  this->children = malloc(this->len_children * sizeof(struct SubBlock));

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
  } else {
    this->global_data = parent->global_data;
  }
};

void block_write(struct Block *this, FILE *out) {
  block_write_head(this, out);
  block_write_body(this, out);
  block_write_tail(this, out);
}

void block_write_head(struct Block *this, FILE *out) {
  struct Symbol *symbol;
  struct SubBlock *child;

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
    if (symbol->location.type != INITIALIZED) {
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
  }

  for (child = this->children; child < (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_body(&(child->value.block), out);
    } else if (child->type == STATEMENT) {
      statement_write(&child->value.statement, out);
    }
  }
}

void block_write_tail(struct Block *this, FILE *out) {
  struct SubBlock *child;
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
  return &(this->children[this->num_children++].value.block);
}

struct Statement *block_add_statement(struct Block *this) {
  while (this->num_children >= this->len_children) {
    __block_grow_children(this);
  }

  this->children[this->num_children].type = STATEMENT;
  statement_init(&(this->children[this->num_children].value.statement), this);
  return &(this->children[this->num_children++].value.statement);
}

void block_get_unique_name(struct Block *this, char *out) {
  sprintf(out, "0_%d", (this->global_data->next_bss_offset + this->global_data->next_data_offset) / 8);
}

struct Symbol *block_add_symbol(struct Block *this, const char *name, struct SymbolType type, struct StorageLocation location) {
  struct Symbol *symbol = (struct Symbol*)malloc(sizeof(struct Symbol));

  // TODO: don't use a constant size for the symbol table...
  symbol_init(symbol, type, this->global_data->next_bss_offset, 8, this, name);
  this->global_data->next_bss_offset += 8;

  HASH_ADD_STR(this->symbol_table, label, symbol);
  return symbol;
}

struct Symbol *block_add_symbol_initialized(struct Block *this, const char *name, enum yytokentype type, const char *initial_value) {
  struct Symbol *symbol = (struct Symbol*)malloc(sizeof(struct Symbol));
  struct SymbolType st;
  st.type = PRIMITIVE;
  st.value.primitive = type;

  // TODO: don't hardcode
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

void statement_init(struct Statement *this, struct Block *parent) {
  // TODO don't hardcode
  this->buffer_size = 512;
  this->buffer = (char*) calloc(this->buffer_size, sizeof(char));
  this->realignment = 0;
  this->parent = parent;
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
  register_get_name(regname, reg);
  sprintf(inst, "pop QWORD %s", reg);
  statement_append_instruction(this, inst);
  this->parent->global_data->stack_size -= 8;
}

void statement_push_int(struct Statement *this, long val) {
  char inst[64];
  sprintf(inst, "push QWORD %d", val);
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
  fprintf(out, "%s", this->buffer);
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

  case REGISTER:
    // I'm pretty sure we don't have to do anything here
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

  case REGISTER:
    register_write_name(this->location.value.regname, out);
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

  case REGISTER:
    register_get_name(this->location.value.regname, out);
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
