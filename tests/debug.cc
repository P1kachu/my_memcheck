#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "colors.hh"
static void print_errno(FILE* OUT)
{
	if (errno)
	{
		fprintf(OUT,
			"%sERROR%s Something went wrong: %s (%s%s%s:%d)\n",
			"\033[31;1m",
			"\033[0m",
			strerror(errno),
			"\033[31;1m",
			__FILE__,
			"\033[0m",
			__LINE__);
	}
}



int main()
{

	fprintf(stdout, "%sEntering main%s\n", CYAN, NONE);

	FILE*  OUT = stdout;

	print_errno(OUT);

	char *t = (char*)malloc(64);

	t[0] = 5;
	t[5] = 5;
	t[63] = 5;
	fprintf(OUT, "%sINVALID%s\n", CYAN, NONE);
	t[64] = 7;
	t[89] = 7;

	free(t);

	return 0;
}
