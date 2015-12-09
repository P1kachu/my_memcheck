#ifndef DEFINES_HH
# define DEFINES_HH

# include <string>

# include <string.h>
# include <unistd.h>
# include <sys/ptrace.h>
# include <sys/types.h>
# include <sys/reg.h>
# include <sys/user.h>
# include <sys/wait.h>
# include <stdio.h>
# include <sys/mman.h>


# include "colors.hh"
# include "helpers.hh"

# define OUT stdout
# define UNUSED(x) { (x) = (x); }

const std::string[] =
{
  "PROT_READ",
  "PROT_WRITE",
  "PROT_EXEC",
  "PROT_NONE"
}

#endif /* !DEFINES_HH */
