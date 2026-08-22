#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int contains_bytes(const char *haystack, const unsigned char *needle, size_t length) {
    size_t haystack_length = strlen(haystack);
    if (length == 0 || length > haystack_length) return 0;
    for (size_t offset = 0; offset + length <= haystack_length; offset++) {
        if (memcmp(haystack + offset, needle, length) == 0) return 1;
    }
    return 0;
}

static int read_all(int fd, unsigned char **bytes, size_t *length) {
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)
            || info.st_size <= 0 || info.st_size > 1024 * 1024) return -1;
    size_t size = (size_t)info.st_size;
    unsigned char *buffer = malloc(size);
    if (buffer == NULL) return -1;
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = read(fd, buffer + offset, size - offset);
        if (count > 0) offset += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else {
            free(buffer);
            return -1;
        }
    }
    *bytes = buffer;
    *length = size;
    return 0;
}

static int verify_file(const char *path, mode_t expected_mode, int check_metadata) {
    struct stat link_info;
    struct stat info;
    if (lstat(path, &link_info) != 0 || !S_ISREG(link_info.st_mode)
            || stat(path, &info) != 0 || !S_ISREG(info.st_mode)
            || info.st_nlink != 1 || (info.st_mode & 0777) != expected_mode
            || info.st_gid != getgid() || getgid() != getegid()
            || getuid() != geteuid()) return 10;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 11;
    unsigned char *first = NULL;
    size_t length = 0;
    if (read_all(fd, &first, &length) != 0) {
        close(fd);
        return 12;
    }
    if (check_metadata) {
        for (int index = 0; environ[index] != NULL; index++) {
            if (contains_bytes(environ[index], first, length)) {
                free(first);
                close(fd);
                return 13;
            }
        }
    }

    if (lseek(fd, 0, SEEK_SET) != 0) {
        free(first);
        close(fd);
        return 14;
    }
    unsigned char seek_byte = 0;
    if (read(fd, &seek_byte, 1) != 1 || seek_byte != first[0]) {
        free(first);
        close(fd);
        return 15;
    }
    close(fd);

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        free(first);
        return 16;
    }
    unsigned char *second = NULL;
    size_t second_length = 0;
    if (read_all(fd, &second, &second_length) != 0
            || second_length != length || memcmp(first, second, length) != 0) {
        free(first);
        free(second);
        close(fd);
        return 17;
    }
    free(second);

    void *mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED || memcmp(mapping, first, length) != 0) {
        if (mapping != MAP_FAILED) munmap(mapping, length);
        free(first);
        close(fd);
        return 18;
    }
    munmap(mapping, length);
    free(first);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 || argv[0] == NULL || argv[1] == NULL || argv[2] == NULL) return 2;
    const char *path = getenv("PROTECTED_FILE");
    if (path == NULL || path[0] != '/') return 3;

    char *end = NULL;
    long parsed_mode = strtol(argv[2], &end, 8);
    if (end == argv[2] || *end != '\0' || parsed_mode < 0 || parsed_mode > 0777) return 4;
    mode_t expected_mode = (mode_t)parsed_mode;
    int is_child = strcmp(argv[1], "--child") == 0;
    if (!is_child && strcmp(argv[1], "--parent") != 0) return 5;

    int result = verify_file(path, expected_mode, !is_child);
    if (result != 0 || is_child) return result;

    pid_t child = fork();
    if (child < 0) return 20;
    if (child == 0) {
        char *child_argv[] = {argv[0], "--child", argv[2], NULL};
        execv(argv[0], child_argv);
        _exit(126);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 21;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 22;
    fputs("file-probe-ok\n", stdout);
    return 0;
}
