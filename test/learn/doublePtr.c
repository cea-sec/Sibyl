#include <stdio.h>

int doublePtr(int** x, int nbElem)
{
	int sum = 0;
	for(nbElem--;nbElem>=0;nbElem--)
		sum += (*x)[nbElem];
	return sum;
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void) {
	int tab[10]={10,1,2,3,4,5,6,7,8,9};
	int* ptr = tab;

	return doublePtr(&ptr, 10);
}
