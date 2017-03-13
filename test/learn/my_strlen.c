#include <stdlib.h>

/**
 * strlen - Find the length of a string
 * @s: The string to be sized
 */
size_t my_strlen(const char * s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

#ifdef __GNUC__
#ifndef __clang__
int main(void) __attribute__((optimize("-O0")));
#endif
#endif
int main(void){
	return my_strlen("Hello world !");
}
