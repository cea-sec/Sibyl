int add(int a, int b) {
	return a+b;
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void){
	return add(42,42);
}
