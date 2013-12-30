#ifndef NBD_DEBUG_H
#define NBD_DEBUG_H
#include <config.h>
/* Debugging macros */
#ifdef DODBG
#define DEBUG(...) printf(__VA_ARGS__)
#else
#define DEBUG(...)
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif

#endif
