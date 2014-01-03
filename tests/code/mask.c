#include <nbdsrv.h>
#include <assert.h>
#include <macro.h>

int main(void) {
	count_assert(getmaskbyte(0) == 0);
	count_assert(getmaskbyte(1) == 0x80);
	count_assert(getmaskbyte(2) == 0xC0);
	count_assert(getmaskbyte(3) == 0xE0);
	count_assert(getmaskbyte(4) == 0xF0);
	count_assert(getmaskbyte(5) == 0xF8);
	count_assert(getmaskbyte(6) == 0xFC);
	count_assert(getmaskbyte(7) == 0xFE);
	count_assert(getmaskbyte(8) == 0xFF);

	return 0;
}
