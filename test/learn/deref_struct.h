typedef struct sub_elem {
	int a;
	unsigned int b;
} sub_elem;

typedef struct elem {
	char *a;
	sub_elem c[10];
} elem;

typedef struct list {
	struct list* next;
	elem elem;
} list;

sub_elem* deref_struct(list* l, unsigned int expected);
