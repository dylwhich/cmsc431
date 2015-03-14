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

"**" {
    /* Exponentiation operator */
    return POW;
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

[a-zA-Z_][a-zA-Z_0-9]* {
    strncpy(yylval.idval, yytext, 63);
    yylval.idval[63] = '\0';
    return ID;
}

[ \t]+ {
    /* Eat whitespace */
}

.|\n {
    /* Return any unmatched character as is */
    return (int)(*yytext);
}

%%
