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

  // In the future... do something?
  return;

  for (child = this->children; child != (this->children + this->num_children); child++) {
    if (child->type == BLOCK) {
      block_write_tail(&(child->value.block), out);
    }
  }
}

struct Block *block_add_child(struct Block *this) {
  char *tmp = alloca(sizeof(char) * 11);
  sprintf(tmp, "%03d", this->num_children);
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

struct Symbol *block_add_symbol(struct Block *this, const char *name, struct SymbolType type) {
  struct Symbol *symbol = (struct Symbol*)malloc(sizeof(struct Symbol));

  // TODO: don't use a constant size for the symbol table...
  symbol_init(symbol, type, this->global_data->next_data_offset, 4, this, name);
  this->global_data->next_data_offset += 4;

  HASH_ADD_STR(this->symbol_table, label, symbol);
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
      // TODO statement_destroy
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

void statement_init(struct Statement *self, struct Block *parent) {
  // TODO
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
  // TODO don't hardcode this
  fprintf(out, "    resq %ld\n", this->size / 8 ? this->size / 8 : 1);
}

void symbol_write_reference(struct Symbol *this, FILE *out) {
  fprintf(out, "[%s+%ld]", this->scope->global_data->data_label);
}
