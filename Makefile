QUIET=-s
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

SRCS_2     = $(addsuffix .cc, $(addprefix src/level2/, mem_strace_hook breaker dig_into_mem))
SRCS_2    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_2    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

SRCS_3     = $(addsuffix .cc, $(addprefix src/level3/, mem_tracker))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level2/, breaker dig_into_mem))
SRCS_3    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
SRCS_3    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

#SRCS_4     = $(addsuffix .cc, $(addprefix src/level4/, ))

#SRCS_4    += $(addsuffix .cc, $(addprefix src/level2/, breaker dig_into_mem))
#SRCS_4    += $(addsuffix .cc, $(addprefix src/level1/, strace syscalls))
#SRCS_4    += $(addsuffix .cc, $(addprefix src/helpers/, helpers))

## OBJ CREATION ##
OBJS_1      = $(SRCS_1:.cc=.o)
OBJS_2      = $(SRCS_2:.cc=.o)
OBJS_3      = $(SRCS_3:.cc=.o)
#OBJS_4      = $(SRCS_4:.cc=.o)

## EXEC NAME ##
EXEC_1      = mem_strace
EXEC_2      = mem_strace_hook
EXEC_3      = mem_tracker
#EXEC_4      = mem_checker


###############################################################################
###############################################################################


# Multi threaded make of the final binary #
multi:
	$(MAKE) $(QUIET) -Bj all

# Produce the final binary   #
all: $(OBJS_1) $(OBJS_2) $(OBJS_3) #$(OBJS_4)
#	$(CXX) $(OBJS_1) $(LDFLAGS) -o $(EXEC_1)
#	$(CXX) $(OBJS_2) $(LDFLAGS) -o $(EXEC_2)
	$(CXX) $(OBJS_3) $(LDFLAGS) -o $(EXEC_3)
#	$(CXX) $(OBJS_4) $(LDFLAGS) -o $(EXEC_4)

# Produce test binary, and launch #
check: distclean multi
	g++ ./tests/debug.cc -o debug
	./$(EXEC_1) ./debug
	./$(EXEC_2) ./debug
	./$(EXEC_3) ./debug
#	./$(EXEC_4) ./debug

# Clean repository           #

clean:
	./utils/repo_cleaner.sh
	$(RM) $(OBJS_1)
	$(RM) $(OBJS_2)
	$(RM) $(OBJS_3)
#	$(RM) $(OBJS_4)

distclean:
	$(RM) debug
	$(RM) $(EXEC_1)
	$(RM) $(EXEC_2)
	$(RM) $(EXEC_3)
#	$(RM) $(EXEC_4)

.PHONY: multi all check clean bonus
