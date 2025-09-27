#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>

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

static char** split_delim(const char *line, char delim, int *out_n){
    int cap = 8, n = 0;
    char **partes = malloc(cap * sizeof(*partes));
    if(!partes){ perror("malloc"); exit(1);}

    const char *start =line, *p =line;
    while(1){
        if(*p == delim || *p == '\0'){
            size_t len = (size_t)(p - start);
            char *frag = malloc(len + 1);
            if(!frag) { perror("malloc"); exit(1); }
            memcpy(frag, start, len);
            frag[len] = '\0';
            
            char *t = trim(frag);
            if(t != frag){ memmove(frag, t, strlen(t) + 1); }

            if(n == cap){ cap *= 2; char **tmp  = realloc(partes, cap * sizeof(*partes));
                if(!tmp) { perror("realloc"); exit(1); } partes = tmp; }
            partes[n++] = frag;

            if(*p == '\0') break;
            start = p + 1;
        }
        ++p;
    }

    if(n == cap){ char **tmp = realloc(partes, (cap+1)*sizeof(*partes));
        if(!tmp){ perror("realloc"); exit(1); } partes = tmp; }
    partes[n] = NULL;
    if(out_n) *out_n = n;
    return partes;
}

static int runnear_comando(char **argv){
    struct sigaction sa_ign = {0}, sa_old = {0};
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sigaction(SIGINT, &sa_ign, &sa_old);

    pid_t pid = fork();
    if(pid <0){
        perror("fork");
        sigaction(SIGINT, &sa_old, NULL);
        return 1;
    }
    if(pid == 0){
        sigaction(SIGINT,&sa_old, NULL);
        execvp(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) == -1 &&errno == EINTR){}
    sigaction(SIGINT, &sa_old, NULL);
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

static int run_pipeline(char **stages, int k){
    if (k <= 0) return 0;

    struct sigaction sa_ign = {0}, sa_old = {0};
    sa_ign.sa_handler = SIG_IGN;
    sigemptyset(&sa_ign.sa_mask);
    sigaction(SIGINT, &sa_ign, &sa_old);

    char ***argvs = malloc(k * sizeof(*argvs));
    if (!argvs) { perror("malloc"); exit(1); }

    for (int i = 0; i < k; ++i){
        argvs[i] = tokenize_argv(stages[i]);
        if(!argvs[i][0]) {
            fprintf(stderr, "mishell: error de sintaxis cerca de '|'\n");
            for(int j = 0; j <= i; ++j) 
            if(argvs[j]) { 
                for(int t = 0; argvs[j][t]; ++t) free(argvs[j][t]); free(argvs[j]); 
            }
            free(argvs);
            sigaction(SIGINT, &sa_old, NULL);
            return 2;
        }
    }

    int num_pipes = k - 1;
    int(*pipes)[2] = NULL;
    if(num_pipes > 0){
        pipes = malloc((size_t)num_pipes * sizeof(int[2]));
        if (!pipes) { perror("malloc"); exit(1); }
        for(int i = 0; i < num_pipes; ++i){
            if(pipe(pipes[i]) == -1) { perror("pipe"); exit(1);}
        }
    }

    pid_t *pids = malloc((size_t)k * sizeof(pid_t));
    if(!pids) { perror("malloc"); exit(1); }

    for (int i = 0; i < k; ++i){
        pid_t pid = fork();
        if (pid < 0){ perror("fork"); exit(1); }
        if (pid == 0) {
            sigaction(SIGINT, &sa_old, NULL);

            if (i > 0) {
                if (dup2(pipes[i - 1][0], STDIN_FILENO) == -1) { perror("dup2"); _exit(1);}
            }
            if (i < k - 1) {
                if (dup2(pipes[i][1], STDOUT_FILENO) == -1) { perror("dup2"); _exit(1); }
            }

            if (num_pipes > 0) {
                for (int j = 0; j < num_pipes; ++j){
                    close(pipes[j][0]);
                    close(pipes[j][1]);
                }
            }

            execvp(argvs[i][0], argvs[i]);
            perror(argvs[i][0]);
            _exit(127);

        } else {
            pids[i] = pid;
        }
    }

    if (num_pipes > 0) {
        for (int j = 0; j < num_pipes; ++j) {
            close(pipes[j][0]);
            close(pipes[j][1]);
        }
    }

    int status = 0, last_status = 0;
    for (int i = 0; i < k; ++i) {
        pid_t w;
        do {w = waitpid(pids[i], &status, 0); } 
        while (w == -1 && errno == EINTR);
        if (w == pids[k - 1]) last_status = status;
    }

    sigaction(SIGINT, &sa_old, NULL);

    for (int i = 0; i < k; ++i) {
        for (int t = 0; argvs[i][t]; ++t) free(argvs[i][t]);
        free(argvs[i]);
    }
    free(argvs);
    free(pids);
    free(pipes);

    if (WIFEXITED(last_status))   return WEXITSTATUS(last_status);
    if (WIFSIGNALED(last_status)) return 128 + WTERMSIG(last_status);
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
        size_t L = strlen(line);
        if (L > 0 && line[L-1] == '\r') line[L-1] = '\0';

        char *t = trim(line);
        if(*t == '\0') {
            continue;
        }

        if(strchr(t, '|') != NULL) {
            int k = 0;
            char **stages = split_delim(t, '|', &k);
            int rc = run_pipeline(stages, k);
            shell_status = rc;

            for (int i = 0; i < k; ++i) free(stages[i]);
            free(stages);
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
    return shell_status;
}