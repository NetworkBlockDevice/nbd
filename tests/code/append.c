#include <nbdsrv.h>
#include <assert.h>
#include <string.h>
#include "macro.h"

int main(void) {
	GArray* arr = NULL;
	SERVER s = {
		.exportname = "my server!",
	};

	count_assert(append_serve(&s, arr) < 0);
	arr = g_array_new(FALSE, FALSE, sizeof(s));
	count_assert(append_serve(&s, arr) == 0);
	s.exportname = "other string";
	SERVER* sp = &g_array_index(arr, SERVER, 0);
	count_assert(strcmp(sp->exportname, "my server!") == 0);
}
