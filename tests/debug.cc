#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

# define print_errno()                                                                      \
        {                                                                                   \
                if (errno)                                                                  \
                {                                                                           \
                        fprintf(OUT, "%sERROR%s Something went wrong: %s (%s%s%s:%d)\n", \
                                "\033[31;1m", "\033[0m", strerror(errno), "\033[31;1m", __FILE__, "\033[0m", __LINE__); \
                }                                                                           \
        }



int main()
{

	FILE*  OUT = stderr;

	char *t = (char*)malloc(0x1000);
	print_errno();
	fprintf(OUT,"100 %d\n", t[0x100]);
	fprintf(OUT,"200 %d\n", t[0x200]);
	fprintf(OUT,"300 %d\n", t[0x300]);
	fprintf(OUT,"400 %d\n", t[0x400]);
	fprintf(OUT,"500 %d\n", t[0x500]);
	fprintf(OUT,"900 %d\n", t[0x900]);
	fprintf(OUT,"1000 %d\n", t[0x1000]);
	fprintf(OUT,"1200 %d\n", t[0x1200]);
	fprintf(OUT,"1300 %d\n", t[0x1300]);
	fprintf(OUT,"1300 %d\n", t[0x13000]);
	free(t);
	return 0;
}
