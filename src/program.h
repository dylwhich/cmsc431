#ifndef _PROGRAM_H
#define _PROGRAM_H

#include "parser.tab.h"
#include "uthash.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define SYMBOL_MAX_LENGTH 64
#define STACK_ALIGNMENT 16

enum StorageLocationType {
  LABEL,
  ADDRESS,
  INITIALIZED,
  REGISTER,
  LOCAL,
  PARAM,
};

enum Register {
  RAX = 0, RBX, RCX, RDX, RSI, RDI,
  R8, R9, R10, R11, R12,
  R13, R14, R15,
  XMM0, XMM1, XMM2, XMM3,
  XMM4, XMM5, XMM6, XMM7,
};

union StorageLocationValue {
  long address;
  enum Register regname;
};
    
struct StorageLocation {
  enum StorageLocationType type;
  union StorageLocationValue value;
};

struct Function {
  enum yytokentype return_type;
  enum yytokentype arg_types[64];
};

enum SymbolTypeType {
  PRIMITIVE,
  USER,
  FUNCTION,
};

union SymbolTypeValue {
  struct Symbol *user;
  enum yytokentype primitive;
  struct Function *function;
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
  char initval[64];
  struct StorageLocation location;
  UT_hash_handle hh;
};

struct Statement {
  long buffer_size;
  char *buffer;
  long realignment;
  struct Block *parent;
  char label[64];
  long int_regs_used[32];
  long float_regs_used[32];
  long call_stack_index;
};

struct StackData {
  long stack_size;
};

struct GlobalData {
  char *bss_label;
  long next_bss_offset;
  char *data_label;
  long next_data_offset;
  long nonce;
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
  long registers[32];
  long next_local;
  struct Function *containing_function;
  struct StackData *stack_data;
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
void block_get_unique_name(struct Block *this, char *out);
struct Symbol *block_add_symbol(struct Block *this, const char *name,
				struct SymbolType type,
				struct StorageLocation location);
struct Symbol *block_add_symbol_initialized(struct Block *this, const char *name,
					    enum yytokentype type,
					    const char *initial_value);
struct Symbol *block_resolve_symbol(struct Block *this, const char *name);

struct SubBlock *block_get_first_child(struct Block *this);

struct SubBlock *block_get_last_child(struct Block *this);

enum Register block_register_acquire_int(struct Block *this);

enum Register block_register_acquire_float(struct Block *this);

long block_register_used(struct Block *this, enum Register reg);

void block_register_release(struct Block *this, enum Register reg);

void block_destroy(struct Block *this);

// PRIVATE!
void __block_grow_children(struct Block *this);
void __block_fix_parents(struct Block *this);

struct SubBlock *subblock_get_prev(struct SubBlock *this);

void statement_init(struct Statement *this, struct Block *parent);
void statement_append_instruction(struct Statement *this,
				  const char *asm_instruction);
void statement_push(struct Statement *this, enum Register regname);
void statement_push_int(struct Statement *this, long val);
void statement_pop(struct Statement *this, enum Register regname);
void statement_grow_stack(struct Statement *this, size_t bytes);
void statement_shrink_stack(struct Statement *this, size_t bytes);
void statement_add_parameter(struct Statement *this, const char *name,
			     enum yytokentype type);
void statement_call_setup(struct Statement *this);
void statement_call_arg(struct Statement *this, struct Symbol *arg);
void statement_call_arg_pop(struct Statement *this, long is_float);
void statement_call_arg_hacky(struct Statement *this, long is_float,
			      const char *argloc);
void statement_call_finish(struct Statement *this, const char *func);
void statement_stack_align(struct Statement *this);
void statement_stack_reset(struct Statement *this);
void statement_write(struct Statement *this, FILE *out);
void statement_destroy(struct Statement *this);

void symbol_init(struct Symbol *this, struct SymbolType type, long offset,
		 size_t size, struct Block *scope, const char *label);
void symbol_write_declaration(struct Symbol *this, FILE *out);
void symbol_write_reference(struct Symbol *this, FILE *out);
void symbol_get_reference(struct Symbol *this, char *out);

void register_write_name(enum Register regname, FILE *out);
void register_get_name(enum Register regname, char *out);

#endif
