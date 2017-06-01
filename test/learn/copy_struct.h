typedef struct elem {
	int a;
	char* b;
	int c[10];
} elem;
typedef long unsigned int size_t;
void copy_struct(elem* in, elem* out);
