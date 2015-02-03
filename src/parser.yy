%{
#include <iostream>
#include <cmath>

/* Parser error reporting routine */
void yyerror(const char *msg);

/* Scannar routine defined by Flex */
int yylex();

using namespace std;
%}

/* yylval union type */
%union {
    long longval;
}

/* Miscellaneous token types */
%token <longval> INTEGER

/* Operators */
%left '+' '-'
%left '*' '/' '%'
%right UMINUS
%right POW

/* Nonterminal types */
%type <longval> expr

%%

start:
expr '\n' { cout << $1 << endl; }
;

expr:
INTEGER           { $$ = $1; }
| expr '+' expr   { $$ = $1 + $3; }
| expr '-' expr   { $$ = $1 - $3; }
| expr '*' expr   { $$ = $1 * $3; }
| expr '/' expr   { $$ = $1 / $3; }
| expr '%' expr   { $$ = $1 % $3; }
| '-' expr        { $$ = -$2; }
| expr POW expr   { $$ = pow($1, $3); }
| '(' expr ')'    { $$ = $2; }
;

%%

void yyerror(const char *msg)
{
    cerr << "Parser error:\n" << msg << endl;
    exit(1);
}

int main()
{
    return yyparse();
}
