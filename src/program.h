#ifndef _PROGRAM_H
#define _PROGRAM_H

#include "parser.tab.h"
#include "uthash.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define SYMBOL_MAX_LENGTH 64

/*
enum StorageLocationType {
  LABEL,
  ADDRESS,
  REGISTER
};

enum Register {
  RAX, RBX, RCX, RDX, RSI, RDI,
  R8, R9, R10, R11, R12,
  R13, R14, R15
};

union StorageLocationValue {
  const long address;
  const Register regname;
};
    
struct StorageLocation {
  const StorageLocationType type;
  const StorageLocationValue value;
};
*/

enum SymbolTypeType {
  PRIMITIVE,
  USER
};

union SymbolTypeValue {
  struct Symbol *user;
  enum yytokentype primitive;
};

struct SymbolType {
  enum SymbolTypeType type;
  union SymbolTypeValue value;
};

struct Symbol {
  struct SymbolType type;
  long offset;
  size_t size;
  struct Block *scope;
  char label[64];
  UT_hash_handle hh;
};

struct Statement {
  char *buffer;
};

struct GlobalData {
  char *data_label;
  long next_data_offset;
};

enum SubBlockType {
  BLOCK,
  STATEMENT
};

struct SubBlock;

struct Block {
  char *name;
  struct Block *parent;
  struct SubBlock *children;
  long num_children;
  long len_children;
  struct Symbol *symbol_table;
  struct GlobalData *global_data;
};

union SubBlockValue {
  struct Block block;
  struct Statement statement;
};

struct SubBlock {
  enum SubBlockType type;
  union SubBlockValue value;
};

void block_init(struct Block *this, const char *name, struct Block *parent);

void block_write(struct Block *this, FILE *out);
void block_write_head(struct Block *this, FILE *out);
void block_write_body(struct Block *this, FILE *out);
void block_write_tail(struct Block *this, FILE *out);

bool block_is_global(struct Block *this);

struct Block *block_add_child(struct Block *this);
struct Block *block_add_named_child(struct Block *this, const char *name);
struct Statement *block_add_statement(struct Block *this);
struct Symbol *block_add_symbol(struct Block *this, const char *name, struct SymbolType type);
struct Symbol *block_resolve_symbol(struct Block *this, const char *name);


void block_destroy(struct Block *this);

// PRIVATE!
void __block_grow_children(struct Block *this);

void statement_init(struct Statement *self, struct Block *parent);

void symbol_init(struct Symbol *this, struct SymbolType type, long offset, size_t size, struct Block *scope, const char *label);
void symbol_write_declaration(struct Symbol *this, FILE *out);
void symbol_write_reference(struct Symbol *this, FILE *out);

#endif
