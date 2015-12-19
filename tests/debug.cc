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

	int fd = open("WHATEVER", O_RDWR|O_CREAT, 0666);

	char *mapped = (char*)mmap(NULL, 0x100, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, fd, 0);


	print_errno(stdout);

	mapped = mapped;

	mapped[0x80] = mapped[0x100];
	mapped[0x100] = mapped[0x80];

	void* t = malloc(90);


	free(t);

	t = malloc(1);

	t = realloc(t, 0x180);

	t = calloc(1, 0x100);

	munmap(mapped, 0x100);

	free(t);

//*/
/*
	char *t = (char*)calloc(1, 0x1000);

	t[3] = 5;


//	*(t + 2) = 5;
//	*(t + 63) = 5;
//	fprintf(OUT, "%sINVALID%s\n", CYAN, NONE);
//	*(t + 64) = 7;

	free(t);
//	fprintf(OUT, "%sFREED%s\n", CYAN, NONE);
//	*(t + 64) = 7;

//	t = (char*)malloc(64);
*/
	return 0;
}
