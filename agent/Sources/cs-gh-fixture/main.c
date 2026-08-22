#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int contains_bytes(const char *haystack, const char *needle, size_t length) {
    size_t haystack_length = strlen(haystack);
    if (length == 0 || length > haystack_length) return 0;
    for (size_t offset = 0; offset + length <= haystack_length; offset++) {
        if (memcmp(haystack + offset, needle, length) == 0) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "auth") == 0
            && strcmp(argv[2], "token") == 0
            && strcmp(argv[3], "--help") == 0) return 0;
    if (argc == 5 && strcmp(argv[1], "auth") == 0
            && (strcmp(argv[2], "status") == 0 || strcmp(argv[2], "token") == 0)
            && strcmp(argv[3], "--hostname") == 0) {
        // The csec preflight requires this isolated probe to report that no
        // ambient keyring/config authentication exists.
        return 1;
    }
    if (argc != 3 || strcmp(argv[1], "api") != 0 || strcmp(argv[2], "user") != 0) return 2;
    const char *directory = getenv("GH_CONFIG_DIR");
    if (directory == NULL || directory[0] != '/'
            || getenv("GH_TOKEN") != NULL || getenv("GITHUB_TOKEN") != NULL
            || getenv("GH_ENTERPRISE_TOKEN") != NULL
            || getenv("GITHUB_ENTERPRISE_TOKEN") != NULL) return 3;

    struct stat directory_info;
    if (lstat(directory, &directory_info) != 0 || !S_ISDIR(directory_info.st_mode)
            || (directory_info.st_mode & 0777) != 0700
            || directory_info.st_gid != getgid()) return 4;

    char path[4096];
    int path_length = snprintf(path, sizeof(path), "%s/hosts.yml", directory);
    if (path_length <= 0 || (size_t)path_length >= sizeof(path)) return 5;
    struct stat file_info;
    if (lstat(path, &file_info) != 0 || !S_ISREG(file_info.st_mode)
            || file_info.st_nlink != 1 || (file_info.st_mode & 0777) != 0400
            || file_info.st_gid != getgid()) return 6;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || file_info.st_size <= 0 || file_info.st_size > 1024 * 1024) return 7;
    size_t length = (size_t)file_info.st_size;
    char *contents = calloc(1, length + 1);
    if (contents == NULL) {
        close(fd);
        return 8;
    }
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, contents + offset, length - offset);
        if (count > 0) offset += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else {
            free(contents);
            close(fd);
            return 9;
        }
    }
    close(fd);

    const char *host = "github.example.test:\n";
    const char *token_prefix = "    oauth_token: '";
    const char *protocol = "\n    git_protocol: https\n";
    const char *user = "    user: 'synthetic-user'\n";
    char *token = strstr(contents, token_prefix);
    char *protocol_line = strstr(contents, protocol);
    if (strncmp(contents, host, strlen(host)) != 0 || token == NULL
            || protocol_line == NULL || strstr(contents, user) == NULL
            || token + strlen(token_prefix) >= protocol_line) {
        free(contents);
        return 10;
    }
    token += strlen(token_prefix);
    size_t token_length = (size_t)(protocol_line - token);
    if (token_length < 3 || token[token_length - 1] != '\'') {
        free(contents);
        return 11;
    }
    token_length--;
    for (int index = 0; index < argc; index++) {
        if (contains_bytes(argv[index], token, token_length)) {
            free(contents);
            return 12;
        }
    }
    for (int index = 0; environ[index] != NULL; index++) {
        if (contains_bytes(environ[index], token, token_length)) {
            free(contents);
            return 13;
        }
    }
    free(contents);
    fputs("gh-profile-ok\n", stdout);
    return 0;
}
