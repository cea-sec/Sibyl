CC = gcc
CFLAGS = -m64

SRC = $(wildcard *.c)
PROGRAMS = $(SRC:.c=)

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(PROGRAMS) $(CLASS) $(CLASSCOMP)
