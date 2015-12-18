#ifndef COLORS_HH
# define COLORS_HH

// Special attributes
#define BOLD         "\033[1m"
#define UND          "\033[4m"
#define BLINK        "\033[5m"
#define INV          "\033[7m"
#define NONE         "\033[0m"

// Colors
#define BLACK       "\033[30;1m"
#define RED         "\033[31;1m"
#define PRED        "\033[31m"
#define GREEN       "\033[32;1m"
#define YELLOW      "\033[33;1m"
#define BLUE        "\033[34;1m"
#define MAGENTA     "\033[35;1m"
#define CYAN        "\033[36;1m"
#define L_GRAY      "\033[37;1m"
#define D_GRAY      "\033[90;1m"
#define L_RED       "\033[91;1m"
#define L_GREEN     "\033[92;1m"
#define L_YELLOW    "\033[93;1m"
#define L_BLUE      "\033[94;1m"
#define L_MAGENTA   "\033[95;1m"
#define L_CYAN      "\033[96;1m"
#define WHITE       "\033[97;1m"
#define C_END       "\033[97;1m"

// Backgrounds
#define B_BLACK     "\033[40m"
#define B_RED       "\033[41m"
#define B_GREEN     "\033[42m"
#define B_YELLOW    "\033[43m"
#define B_BLUE      "\033[44m"
#define B_MAGENTA   "\033[45m"
#define B_CYAN      "\033[46m"
#define B_L_GRAY    "\033[47m"
#define B_D_GRAY    "\033[100m"
#define B_L_RED     "\033[101m"
#define B_L_GREEN   "\033[102m"
#define B_L_YELLOW  "\033[103m"
#define B_L_BLUE    "\033[104m"
#define B_L_MAGENTA "\033[105m"
#define B_L_CYAN    "\033[106m"
#define B_WHITE     "\033[107m"
#define B_END       "\033[49m"

#endif /* !COLORS_HH */
