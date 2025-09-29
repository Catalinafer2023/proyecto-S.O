integrantes: Fernanda Rubilar Sánchez , Matias Concha Aguilera


Como compilar y ejecutar:

- Compilacion : gcc -std=c11 -Wall -Wextra -O2 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE mishell.c -o mishell

- Ejecucion: 
./mishell
y se vera el prompt
mishell:$

Ejemplos de uso:

Comandos simples:
mishell:$ echo hola
hola
mishell:$ noexiste
noexiste: No such file or directory

Salir de la shell:
mishell:$ exit
mishell:$ exit 7     #con codigo de salida

Pipes: 
mishell:$ echo hola | tr a-z A-Z
HOLA
mishell:$ ps aux | sort -nr -k 4 | head -5

miprof (perfilado de comandos):

Mostrar métricas:
mishell:$ miprof ejec echo hola


Guardar métricas (append) en un archivo:
mishell:$ miprof ejecsave resultados.txt ls -l


Ejecutar con timeout (no guarda, mata el proceso si excede):
mishell:$ miprof ejecutar 2 sleep 5

