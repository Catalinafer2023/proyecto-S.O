#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PROMPT "mishell:$ "

static void print_prompt(void){
    if(isatty(STDIN_FILENO)){
        (void)write(STDOUT_FILENO, PROMPT, sizeof(PROMPT) - 1);
    }
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;

    for(;;) {
        print_prompt();

        ssize_t n = getline(&line , &cap, stdin);
        if(n == -1){
            if (isatty(STDIN_FILENO)) write(STDOUT_FILENO, "\n", 1);
            break;
        }
    }

    free(line);
    return 0;
}