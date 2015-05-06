%{
#include <stdlib.h>
#include <string.h>
#include "parser.tab.h"
%}

%%

\"[^"\n]*["\n] {
    yylval.stringval = strdup(yytext);
    return STRING;
}

[[:digit:]]+ {
    /* Integers */
    yylval.longval = atol(yytext);
    return INTEGER;
}

[[:digit:]]*[.][[:digit:]]+ {
    /* Floats */
    yylval.floatval = atof(yytext);
    return FLOAT;
}

"true" {
  yylval.boolval = 1;
  return BOOL;
}

"false" {
  yylval.boolval = 0;
  return BOOL;
}

"void" {
  return VOID;
}

"**" {
    /* Exponentiation operator */
    return POW;
}

"and" {
    /* Boolean And */
    return BOOL_AND;
}

"or" {
    /* Boolean And */
    return BOOL_OR;
}

"xor" {
    /* Boolean And */
    return BOOL_XOR;
}

"==" {
    /* Boolean Equal */
    return BOOL_EQUAL;
}

"!=" {
    /* Boolean Not-Equal */
    return BOOL_NOT_EQUAL;
}

"<=" {
    /* Boolean Less-Than-Or-Equal */
    return BOOL_LESS_EQUAL;
}

">=" {
    /* Boolean Greater-Than-Or-Equal */
    return BOOL_GREATER_EQUAL;
}

"readint" {
    return READINT;
}

"readfloat" {
    return READFLOAT;
}

"printl" {
    /* Print-line statement */
    return PRINTL;
}

"print" {
    /* Print statement */
    return PRINT;
}

"int" {
    return INTTYPE;
}

"float" {
    return FLOATTYPE;
}

"bool" {
    return BOOLTYPE;
}

"if" {
    return IF;
}

"else" {
    return ELSE;
}

"while" {
    return WHILE;
}

"pass" {
    return NOP;
}

[a-zA-Z_][a-zA-Z_0-9]* {
    strncpy(yylval.idval, yytext, 63);
    yylval.idval[63] = '\0';
    return ID;
}

[ \t\n]+ {
    /* Eat whitespace */
}

.|\n {
    /* Return any unmatched character as is */
    return (int)(*yytext);
}

%%
