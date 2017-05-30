#include "deref_struct.h"

sub_elem* deref_struct(list* l, unsigned int expected) {
	int i;
	for (;;) {
		for (i = 0; i < 10; i++) {
			if (l->elem.c[i].b == expected) {
				return &(l->elem.c[i]);
			}
		}
		l = l->next;
	}
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void) {
	list tab[3];
	tab[0].next = &tab[1];
	tab[1].next = &tab[2];

	tab[2].elem.c[4].b = 0x1337;
	deref_struct(&tab[0], 0x1337);
	return 0;
}
