%{
extern int yylex();
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "nbdclt.h"
typedef char * YYSTYPE;
%}

%define parse.trace
%define api.value.type {char *}

%token SPACE
%token STRING

%%

nbdtab:
	%empty
	| '\n' nbdtab
	| mountdef nbdtab
;

mountdef:
	STRING SPACE STRING SPACE STRING optlist { nbdtab_commit_line($1, $3, $5); }
;

optlist:
	%empty
	| SPACE options
;

options:
	options ',' option
	| option
;

option:
	STRING			{ nbdtab_set_flag($1); }
	| STRING '=' STRING	{ nbdtab_set_property($1, $3); }
;
