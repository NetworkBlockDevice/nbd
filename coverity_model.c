
typedef struct _GArray GArray;
#define g_array_append_val(a, v) g_array_append_vals(a, &(v), 1)

GArray* g_array_append_vals(GArray*, void*, unsigned int) {
	__coverity_escape__;
}
