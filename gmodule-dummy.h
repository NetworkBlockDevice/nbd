/* Header file with dummy function stubs for what gmodule usually
 * provides us.
 */

/* First, make sure the programmer isn't making a big mistake */
#ifndef GMODULE_DUMMY_H
#define GMODULE_DUMMY_H
#if WITH_PLUGINS
#error "dummy modules header being used when it shouldn't be"
#endif

#include <glib.h>

typedef struct _GModule	GModule;
typedef const gchar* (*GModuleCheckInit)(GModule* module);
typedef void (*GModuleUnload)(GModule* module);

#define G_MODULE_BIND_LAZY 1
#define G_MODULE_BIND_LOCAL 2

static inline GModule* g_module_open(name, flags) {
	return NULL;
}

static inline gboolean g_module_close(handle) {
	return FALSE;
}

static inline gboolean g_module_supported(void) {
	return FALSE;
}

static inline gboolean g_module_symbol(GModule* module, const gchar* symbol_name, gpointer* symbol) {
	return FALSE;
}

static inline gchar* g_module_build_path(const gchar* directory, const gchar* module_name) {
	return "Don't use g_module_build_path for anything but modules, please";
}

static inline gchar* g_module_error(void) {
	return "Plugin support not compiled in to nbd-server. Please make sure libgmodule is installed, and that you have not compiled with --disable-plugins";
}

#endif //GMODULE_DUMMY_H
