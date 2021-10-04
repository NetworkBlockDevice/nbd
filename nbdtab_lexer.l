%{
#include "nbdtab_parser.tab.h"
%}

%option noyywrap

%%

#[^\n]*\n	{ /* ignoring comments */ }
[ \t]+		{ yylval = strdup(yytext); return SPACE; }
[^ \t\n,=.]+	{ yylval = strdup(yytext); return STRING; }
.		{ yylval = strdup(yytext); return *yytext; }
\n		{ yylval = strdup(yytext); return *yytext; }
