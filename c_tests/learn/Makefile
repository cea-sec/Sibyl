CC = gcc
CFLAGS = -m64

SRC = $(wildcard *.c)
PROGRAMS = $(SRC:.c=)
CLASS = $(SRC:.c=.py)
CLASSCOMP = $(SRC:.c=.pyc)

all: $(PROGRAMS)

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(PROGRAMS) $(CLASS) $(CLASSCOMP)
