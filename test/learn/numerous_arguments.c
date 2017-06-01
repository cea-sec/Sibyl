#include <stdio.h>

unsigned int numerous_arguments(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f, unsigned int g, unsigned int h, unsigned int i, unsigned int j, unsigned int k, unsigned int l, unsigned int m, unsigned int n, unsigned int o) {
	return a+b+c+d+e+f+g+h+i+j+k+l+m+n+o;
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void){
	return numerous_arguments(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)+numerous_arguments(1,1,1,1,1,1,1,1,1,1,1,1,1,1,1);
}
