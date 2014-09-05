CC := gcc
CFLAGS := -m32 -O0 --static
PROGRAMS := test_string test_stdlib test_ctype

all: $(PROGRAMS)

.c.c:
	$(CC) $(CFLAGS) $< -o $@

test_string: test_string.c
test_stdlib: test_stdlib.c
test_ctype: test_ctype.c

clean:
	rm -f $(PROGRAMS)