###############################################################################

## COMPILER ##
CXX       = g++

## FLAGS ##
CXXFLAGS  = -Wall -Wextra -Werror -pedantic  -std=c++14  -I $(INCLDIR)
CXXFLAGS += -pedantic -g
CXXFLAGS += -Wundef -Wshadow -Wpointer-arith -Wcast-qual
CXXFLAGS += -Wcast-align
CXXFLAGS += -Wmissing-declarations
CXXFLAGS += -Wunreachable-code -fdiagnostics-color=always

## LIBRARY ##
LDLIBS    = -lsfml-graphics -lsfml-window -lsfml-system -lsfml-audio

## INCLUDES DIRECTORY ##
INCLDIR   = src/includes/

## MAIN ##
SRCS     = $(addsuffix .cc, $(addprefix src/, main game))
#SRCS     = $(addsuffix .cc, $(addprefix src/, map_main))
#SRCS     = $(addsuffix .cc, $(addprefix tests/, tests)) # Testing

## CHARACTER ##
SRCS     += $(addsuffix .cc, $(addprefix src/character/, ennemy character hero intersect))

## SPRITE ##
SRCS     += $(addsuffix .cc, $(addprefix src/sprite/, sprite))

## MAP ##
SRCS     += $(addsuffix .cc, $(addprefix src/map/, map))

## EXECEPTIONS ##
SRCS     += $(addsuffix .cc, $(addprefix src/exception/, invalid-game-value))

## UTILS ##
SRCS     += $(addsuffix .cc, $(addprefix src/utils/, utils))

## MENU ##
SRCS     += $(addsuffix .cc, $(addprefix src/menu/, menu pause save load))

## GM ##
SRCS     += $(addsuffix .cc, $(addprefix src/gm/, gm))

## EFFECTS ##
SRCS     += $(addsuffix .cc, $(addprefix src/effects/, effects))

## GAME ##
SRCS     += $(addsuffix .cc, $(addprefix src/gameover/, gameover))
SRCS     += $(addsuffix .cc, $(addprefix src/youwin/, youwin))

## OBJ CREATION ##
OBJS      = $(SRCS:.cc=.o)

## EXEC NAME ##
EXEC      = game

###############################################################################

# Multi threaded make of the final binary #
multi:
	$(MAKE) -j all

# Produce the final binary   #
all: $(OBJS)
	$(CXX) $(OBJS) $(LDLIBS) -o $(EXEC)

# Produce test binary, and launch #
check: multi
	./$(EXEC)

# Clean repository           #
clean:
	$(RM) $(OBJS) $(EXEC)

.PHONY: multi all check clean

###############################################################################
