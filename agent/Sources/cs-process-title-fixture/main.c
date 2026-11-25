#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

// Synthetic data only. Modern Ruby clears the original argv string area when
// `$PROGRAM_NAME` changes. Process-list code that still expects the original
// argc can then walk into the adjacent initial environment. This tiny fixture
// reproduces that memory shape without requiring a particular Ruby version.
int main(int argc, char **argv) {
    if (argc < 4 || argv[0] == NULL || argv[1] == NULL
            || environ == NULL || environ[0] == NULL) return 2;

    char *argument_start = argv[0];
    char *environment_start = environ[0];
    if (environment_start <= argument_start) return 2;

    size_t argument_capacity = (size_t)(environment_start - argument_start);
    size_t title_length = strlen(argv[1]);
    if (title_length == 0 || title_length + 1 > argument_capacity) return 2;
    char *title = strdup(argv[1]);
    if (title == NULL) return 2;

    memset(argument_start, 0, argument_capacity);
    memcpy(argument_start, title, title_length);
    free(title);

    fputs("ready\n", stdout);
    fflush(stdout);
    sleep(30);
    return 0;
}
