#ifndef TEST_MACRO_H
#define TEST_MACRO_H

#include <stdio.h>

static int test_macro_counter = 0;
#define count_assert(EXPR) { printf("%d\n", ++test_macro_counter); assert(EXPR); }

#endif
