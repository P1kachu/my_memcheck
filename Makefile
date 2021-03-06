# LSE RECRUITEMENT 2016 - my_memcheck
#
# Project was supposed to be done in C++
# But I found some of it to be easier to do
# in C. Like 90% of it. So lets say it was done
# in C+ only.
#
# With love,
# P1kachu.

QUIET=#-s
## COMPILER ##
CXX       = g++

## FLAGS ##
CXXFLAGS  = -Wall -Wextra -Werror -pedantic  -std=c++11 -I $(INCLDIR)
CXXFLAGS += -pedantic -g
CXXFLAGS += -Wundef -Wshadow -Wpointer-arith -Wcast-qual
CXXFLAGS += -Wcast-align
CXXFLAGS += -Wmissing-declarations
CXXFLAGS += -Wunreachable-code
CXXFLAGS += -fdiagnostics-color=always
CXXFLAGS += -O3

## INCLUDES DIRECTORY ##
INCLDIR   = src/includes/

## LIBS ##
LDFLAGS = -lcapstone

## MAIN ##
SRCS_1     = $(addsuffix .cc, $(addprefix src/level1/, strace syscalls mem_strace))
SRCS_1    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_2     = $(addsuffix .cc, $(addprefix src/level4/, injector sanity_check))
SRCS_2    += $(addsuffix .cc, $(addprefix src/level3/, tracker))
SRCS_2    += $(addsuffix .cc, $(addprefix src/level2/, mem_strace_hook breaker dig_into_mem))
SRCS_2    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_2    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_3     = $(addsuffix .cc, $(addprefix src/level4/, injector sanity_check))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level3/, mem_tracker tracker))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level2/, breaker dig_into_mem))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_3    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_4     = $(addsuffix .cc, $(addprefix src/level4/, mem_checker injector sanity_check))
SRCS_4    += $(addsuffix .cc, $(addprefix src/level3/, tracker))
SRCS_4    += $(addsuffix .cc, $(addprefix src/level2/, breaker dig_into_mem))
SRCS_4    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_4    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

## EXEC NAME ##
EXEC_1      = mem_strace
EXEC_2      = mem_strace_hook
EXEC_3      = mem_tracker
EXEC_4      = mem_checker


###############################################################################
###############################################################################


# Multi threaded make of the final binary #
multi:
	$(MAKE) $(QUIET) -j all

# Produce the final binary   #
all: libhooks debug
	$(MAKE) -B level1
	$(MAKE) -B level2
	$(MAKE) -B level3
	$(MAKE) -B level4
	clear

# Produce Level4 binary
level1: debug
	@echo -en "\033[31;1mCompiling level 1... "
	@$(CXX) $(CXXFLAGS) -D LEVEL=1 $(SRCS_1) $(LDFLAGS) -o $(EXEC_1)
	@echo -e "\033[32;1mDone.\033[0m"
level2: debug
	@echo -en "\033[31;1mCompiling level 2... "
	@$(CXX) $(CXXFLAGS) -D LEVEL=2 $(SRCS_2) $(LDFLAGS) -o $(EXEC_2)
	@echo -e "\033[32;1mDone.\033[0m"
level3: libhooks debug
	@echo -en "\033[31;1mCompiling level 3... "
	@$(CXX) $(CXXFLAGS) -D LEVEL=3 $(SRCS_3) $(LDFLAGS) -o $(EXEC_3)
	@echo -e "\033[32;1mDone.\033[0m"
level4: libhooks debug
	@echo -en "\033[31;1mCompiling level 4... "
	@$(CXX) $(CXXFLAGS) -D LEVEL=4 $(SRCS_4) $(LDFLAGS) -o $(EXEC_4)
	@echo -e "\033[32;1mDone.\033[0m"


# Produce debug binary #
debug:
#	gcc ./tests/debug.cc -o c.o
#	nasm -f elf64 casm.asm -o casm.o
#	ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -lc casm.o c.o -o debug
	gcc -Wall -Wextra -Werror -I src/includes ./tests/debug.cc -o ./debug

libhooks:
	gcc -Wall -Wextra -Werror -shared -I src/includes -fPIC -ldl src/level3/memory_hooks.c -o libhooks.so

# Produce test binary, and launch #
check:  distclean libhooks debug multi
	clear
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m"
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m\n\n"
	./$(EXEC_1) ./debug 2> /dev/null
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m\n\n"
	./$(EXEC_2) ./debug 2> /dev/null
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m\n\n"
	./$(EXEC_3) ./debug 2> /dev/null
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m\n\n"
	./$(EXEC_3) --preload ./libhooks.so ./debug 2> /dev/null
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m\n\n"
	./$(EXEC_4) --preload ./libhooks.so ./debug

# Clean repository           #

clean:
	./utils/repo_cleaner.sh

distclean: clean
	$(RM) debug
	$(RM) $(EXEC_1)
	$(RM) $(EXEC_2)
	$(RM) $(EXEC_3)
	$(RM) $(EXEC_4)
	$(RM) libhooks
	$(RM) WHATEVER

.PHONY: multi all clean bonus libhook debug distclean
