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
    fprintf(out, ".data\n");
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
  
}

struct Symbol *block_resolve_symbol(struct Block *this, const char *name) {
  struct Symbol *result;
  HASH_FIND_STR(this->symbol_table, name, result);
}

bool block_is_global(struct Block *this) {
  return this->parent == NULL;
}

void block_destroy(struct Block *this) {
  free(this->name);
  this->name = NULL;

  free(this->children);
  this->children = NULL;

  if (block_is_global(this)) {
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


void symbol_init(struct Symbol *this, struct SymbolType type, long offset, struct Block *scope, const char *label) {
  this->type = type;
  this->offset = offset;

  this->scope = scope;

  strncpy(this->label, label, MAX_SYMBOL_LENGTH);
  this->label[MAX_SYMBOL_LENGTH-1] = '\0';
}

void symbol_write_declaration(struct Symbol *this, FILE *out) {
  fprintf(out, "    dq ?\n");
}

void symbol_write_reference(struct Symbol *this, FILE *out) {
  fprintf(out, "[%s+%ld]", this->scope->global_data->data_label);
}
