#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "colors.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void print_errno(FILE* OUT);
void print_errno(FILE* OUT)
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

//	fprintf(stdout, "%sEntering main%s\n", CYAN, NONE);

//	FILE*  OUT = stdout;

//	print_errno(OUT);

	errno = 0;
	int fd = open("debug.cc", O_RDONLY);
	print_errno(stdout);
	char *mapped = (char*)mmap(NULL, 0x100, PROT_READ, MAP_SHARED, fd, 0);
	print_errno(stdout);
	char *t = (char*)malloc(0x1000);

	mapped[0x10] = 0;
	mapped[0x50] = 0;

	mapped[0x99] = 0;

	mapped[0x100] = 0;

	mapped[0x101] = 0;

//	*(t + 1) = 5;
//	*(t + 2) = 5;
//	*(t + 63) = 5;
//	fprintf(OUT, "%sINVALID%s\n", CYAN, NONE);
//	*(t + 64) = 7;
//	*(t + 89) = 7;

//	free(t);
//	fprintf(OUT, "%sFREED%s\n", CYAN, NONE);
//	*(t + 64) = 7;
	t[89] = 7;

//	t = (char*)malloc(64);

	return 0;
}
