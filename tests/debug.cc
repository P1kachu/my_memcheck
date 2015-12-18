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


	int fd = open("WHATEVER", O_RDWR|O_CREAT, 0666);

	char *mapped = (char*)mmap(NULL, 0x100, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, fd, 0);


	print_errno(stdout);

	mapped = mapped;

	mapped[1] = 5;
	mapped[0x9f] = 5;
	printf("Hello %p\n", (void*)mapped);
	mapped[0x100] = 5;
	mapped[0x101] = 5;
	mapped[0x102] = 5;

	mapped[0x80] = 5;


	int i = mapped[0];
        i = mapped[80];
        i = mapped[100];

	munmap(mapped, 0x80);


	int *t = (int*)calloc(1, 0x1000);

	*(t + i) = 5;
//	*(t + 2) = 5;
//	*(t + 63) = 5;
//	fprintf(OUT, "%sINVALID%s\n", CYAN, NONE);
//	*(t + 64) = 7;

//	free(t);
//	fprintf(OUT, "%sFREED%s\n", CYAN, NONE);
//	*(t + 64) = 7;

//	t = (char*)malloc(64);

	return 0;
}
