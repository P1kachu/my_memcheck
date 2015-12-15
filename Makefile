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

SRCS_2     = $(addsuffix .cc, $(addprefix src/level2/, mem_strace_hook breaker dig_into_mem))
SRCS_2    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_2    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_3     = $(addsuffix .cc, $(addprefix src/level3/, injector))
SRCS_3     = $(addsuffix .cc, $(addprefix src/level3/, mem_tracker tracker))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level2/, breaker dig_into_mem))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_3    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_4     = $(addsuffix .cc, $(addprefix src/level4/, mem_checker injector))
SRCS_4    += $(addsuffix .cc, $(addprefix src/level3/, tracker))
SRCS_4    += $(addsuffix .cc, $(addprefix src/level2/, breaker dig_into_mem))
SRCS_4    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_4    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

## OBJ CREATION ##
OBJS_1      = $(SRCS_1:.cc=.o)
OBJS_2      = $(SRCS_2:.cc=.o)
OBJS_3      = $(SRCS_3:.cc=.o)
OBJS_4      = $(SRCS_4:.cc=.o)

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
all: libhooks debug $(OBJS_1) $(OBJS_2) $(OBJS_3) $(OBJS_4)
	$(CXX) $(OBJS_1) $(LDFLAGS) -o $(EXEC_1)
	$(CXX) $(OBJS_2) $(LDFLAGS) -o $(EXEC_2)
	$(CXX) $(OBJS_3) $(LDFLAGS) -o $(EXEC_3)
	$(CXX) $(OBJS_4) $(LDFLAGS) -o $(EXEC_4)
	clear

# Produce debug binary #
debug:
#	gcc ./tests/debug.cc -o c.o
#	nasm -f elf64 casm.asm -o casm.o
#	ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -lc casm.o c.o -o debug
	$(CXX) ./tests/debug.cc -o ./debug

libhooks:
	gcc -Wall -Wextra -Werror -shared -I src/includes -fPIC -ldl src/level3/memory_hooks.c -o libhooks.so

# Produce test binary, and launch #
check: libhooks distclean multi
	clear
	@echo -e "\033[33;1m##################################################################################\
#######################\033[0m\n\n"
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
#	./$(EXEC_4) ./debug

# Clean repository           #

clean:
	./utils/repo_cleaner.sh
	$(RM) $(OBJS_1)
	$(RM) $(OBJS_2)
	$(RM) $(OBJS_3)
	$(RM) $(OBJS_4)

distclean:
	$(RM) debug
	$(RM) $(EXEC_1)
	$(RM) $(EXEC_2)
	$(RM) $(EXEC_3)
	$(RM) $(libhooks)
	$(RM) $(EXEC_4)

.PHONY: multi all clean bonus libhook debug distclean
