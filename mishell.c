#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/wait.h>
#include <errno.h>

#define PROMPT "mishell:$ "

// ---------- trim in-place (retorna el puntero al primer no espacio)-----
static char* trim(char *s){
    if(!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    if(*s == '\0') return s;
    char *end = s + strlen(s) -1;
    while(end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

//------------ tokenizador por espacios y tabs -------------
static char** tokenize_argv(const char *line){
    int cap = 8, n = 0;
    char **argv = malloc(cap * sizeof(*argv));
    if(!argv) { perror("malloc"); exit(1);}

    char *copy = strdup(line);
    if(!copy){ perror("strdup"); exit(1);}

    char *tok = strtok(copy, " \t");
    while(tok){
        if(n == cap){
            cap *= 2;
            char **tmp = realloc(argv, cap * sizeof(*argv));
            if (!tmp) { perror("realloc"); free(argv); free(copy); exit(1);}
            argv = tmp;
        }
        argv[n++] = strdup(tok);
        tok = strtok(NULL, " \t");
    }

    if(n == cap){
        char **tmp = realloc(argv, (cap + 1) * sizeof(*argv));
        if(!tmp) { perror("realloc"); free(argv); free(copy); exit(1);}
        argv = tmp;
    }
    argv[n] = NULL;

    free(copy);
    return argv;
}

static int runnear_comando(char **argv){
    pid_t pid = fork();
    if(pid <0){
        perror("fork");
        return 1;
    }
    if(pid == 0){
        execvp(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) == -1 &&errno == EINTR){}
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

static void free_argv(char **argv) {
    if (!argv) return;
    for (int i = 0; argv[i]; ++i) free(argv[i]);
    free(argv);
}

static void print_prompt(void){
    if(isatty(STDIN_FILENO)){
        (void)write(STDOUT_FILENO, PROMPT, sizeof(PROMPT) - 1);
    }
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    int shell_status = 0;

    for(;;) {
        print_prompt();

        ssize_t n = getline(&line , &cap, stdin);
        if(n == -1){
            if (isatty(STDIN_FILENO)) write(STDOUT_FILENO, "\n", 1);
            break;
        }

        if (n > 0 && line[n-1] == '\n') line[n-1] = '\0';

        char *t = trim(line);
        if(*t == '\0') {
            continue;
        }

        char **argv = tokenize_argv(t);
        if(!argv[0]) {
            free_argv(argv);
            continue;
        }
        
        if(strcmp(argv[0], "exit") == 0){
            if(argv[1] == NULL){
                free_argv(argv);
                break;
            } 
            if (argv[2] != NULL){
                fprintf(stderr, "exit: demasiados argumentos\n");
                free_argv(argv);
                continue;
            } 
        
            char *end = NULL;
            long v = strtol(argv[1], &end, 10);
            if(argv[1][0] == '\0' || *end != '\0'){
                fprintf(stderr, "exit: argumento no numerico: %s\n", argv[1]);
                free_argv(argv);
                continue;
                }

            shell_status = (int)(v & 0xFF);
            free_argv(argv);
            break;
        }

        int rc = runnear_comando(argv);
        shell_status = rc;
        free_argv(argv);
    }

    free(line);
    return 0;
}