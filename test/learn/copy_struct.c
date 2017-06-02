#include "copy_struct.h"

void* my_memcpy(void *dest,const void *src, size_t n)
{
	size_t i;
	void *tmp = dest;

	for (i = 0;i < n; i++) {
		*(char*)dest++ = *(char*)src++;
	}
	return tmp;
}

void copy_struct(elem* in, elem* out) {
	my_memcpy((char*) out, (char *)in, sizeof(elem));
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void) {
	elem e1, e2;
	e1.a = 4;
	copy_struct(&e1, &e2);
	return 0;
}
