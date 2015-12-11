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
#CXXFLAGS += -O3

## INCLUDES DIRECTORY ##
INCLDIR   = src/includes/

## LIBS ##

LDFLAGS = -lcapstone

## MAIN ##
SRCS_1     = $(addsuffix .cc, $(addprefix src/level1/, strace syscalls mem_strace))
SRCS_1    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_2     = $(addsuffix .cc, $(addprefix src/level2/, mem_strace_hook breaker))
SRCS_2    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

## OBJ CREATION ##
OBJS_1      = $(SRCS_1:.cc=.o)
OBJS_2      = $(SRCS_2:.cc=.o)

## EXEC NAME ##
EXEC_1      = mem_strace
EXEC_2      = mem_strace_hook

# Multi threaded make of the final binary #
multi:
	$(MAKE) $(QUIET) -Bj all

# Produce the final binary   #
all: $(OBJS_1) $(OBJS_2)
	$(CXX) $(OBJS_1) $(LDFLAGS) -o $(EXEC_1)
	$(CXX) $(OBJS_2) $(LDFLAGS) -o $(EXEC_2)

# Produce test binary, and launch #
check: clean multi
	./$(EXEC_1) ./hardcoded
	./$(EXEC_2)

# Clean repository           #
clean:
	./utils/repo_cleaner.sh
	$(RM) $(OBJS_1) $(EXEC_1)
	$(RM) $(OBJS_2) $(EXEC_2)

.PHONY: multi all check clean bonus
