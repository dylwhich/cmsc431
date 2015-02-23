#include "program.h"
#include "uthash.h"

#include <malloc.h>
#include <stdbool.h>
#include <string.h>
#include <alloca.h>

void block_init(struct Block *this, const char *name, struct Block *parent) {
  this->symbol_table = NULL;

  this->name = malloc(strlen(name) + 1);
  strcpy(this->name, name);
  this->name[strlen(name)] = '\0';

  this->parent = parent;

  this->len_children = 4;
  this->num_children = 0;
  this->children = malloc(this->len_children * sizeof(struct Block));

  // Keep the global data in sync with all the blocks
  if (block_is_global(this)) {
    this->global_data = malloc(sizeof(struct GlobalData));
    this->global_data->next_data_offset = 0;
    this->global_data->data_label = malloc(8 * sizeof(char));
    strcpy(this->global_data->data_label, "globals");
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
    fprintf(out, "SECTION .bss\n");
  }

  for (symbol=this->symbol_table; symbol != NULL; symbol = symbol->hh.next) {
    symbol_write_declaration(symbol, out);
  }

  for (child = this->children; child != (this->children + this->num_children); child++) {
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
    fprintf(out, "main:\n");
  }

  for (child = this->children; child != (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_body(&(child->value.block), out);
    } else if (child->type == STATEMENT) {
      fprintf(out, "%s", child->value.statement.buffer);
    }
  }
}

void block_write_tail(struct Block *this, FILE *out) {
  struct SubBlock *child;
  for (child = this->children; child != (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_tail(&(child->value.block), out);
    }
  }
  // TODO is this actually right?
  fprintf(out, "mov rsp, rbp\n");
  fprintf(out, "mov rbp\n");
  fprintf(out, "ret\n");
}

struct Block *block_add_child(struct Block *this) {
  // TODO don't hardcode this, somehow?
  char *tmp = (char*) alloca(sizeof(char) * 11);
  sprintf(tmp, "%03ld", this->num_children);
  return block_add_named_child(this, tmp);
}

struct Block *block_add_named_child(struct Block *this, const char *name) {
  char *tmp = alloca(sizeof(char) * (strlen(name) + strlen(this->name) + 2));
  sprintf(tmp, "%s_%s", this->name, name);

  while (this->num_children >= this->len_children) {
    __block_grow_children(this);
  }

  block_init(&(this->children[this->num_children].value.block), tmp, this);
  return &(this->children[this->num_children++].value.block);
}

struct Statement *block_add_statement(struct Block *this) {
  while (this->num_children >= this->len_children) {
    __block_grow_children(this);
  }

  statement_init(&(this->children[this->num_children].value.statement), this);
  return &(this->children[this->num_children++].value.statement);
}

struct Symbol *block_add_symbol(struct Block *this, const char *name, struct SymbolType type, struct StorageLocation location) {
  struct Symbol *symbol = (struct Symbol*)malloc(sizeof(struct Symbol));

  // TODO: don't use a constant size for the symbol table...
  symbol_init(symbol, type, this->global_data->next_data_offset, 4, this, name);
  this->global_data->next_data_offset += 4;

  HASH_ADD_STR(this->symbol_table, label, symbol);
  return symbol;
}

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

  for (child = this->children; child != (this->children + this->num_children); child++) {
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
  this->buffer = (char*) malloc(sizeof(char) * this->buffer_size);
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

void symbol_init(struct Symbol *this, struct SymbolType type, long offset,
		 size_t size, struct Block*scope, const char *label) {
  this->type = type;
  this->offset = offset;
  this->size = size;

  this->scope = scope;

  strncpy(this->label, label, SYMBOL_MAX_LENGTH);
  this->label[SYMBOL_MAX_LENGTH-1] = '\0';
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
    fprintf(out, "qword [%s+%ld]", this->scope->global_data->data_label, this->offset);
    break;

  case ADDRESS:
    fprintf(out, "qword [%ld]", this->location.value.address);
    break;

  case REGISTER:
    register_write_name(this->location.value.regname, out);
    break;
  }
}
