int several_traces(int a, int b, unsigned char addOrMul){
	if( addOrMul )
		return a+b;
	else
		return a*b;
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void) {
	return several_traces(42,42,0)+several_traces(-42,1337,1)+several_traces(4,2,0);
}
