#include "CSECSecretHeuristics.h"

#include <math.h>
#include <stdbool.h>
#include <string.h>

static uint8_t
cs_upper_name_byte(uint8_t byte)
{
    if (byte >= 'a' && byte <= 'z') {
        return (uint8_t)(byte - ('a' - 'A'));
    }
    return byte == '-' ? '_' : byte;
}

static bool
cs_name_contains_marker(const uint8_t *name, size_t name_length,
    const char *marker)
{
    const size_t marker_length = strlen(marker);
    if (marker_length > name_length) {
        return false;
    }
    for (size_t start = 0; start + marker_length <= name_length; start++) {
        bool matches = true;
        for (size_t offset = 0; offset < marker_length; offset++) {
            if (cs_upper_name_byte(name[start + offset]) !=
                (uint8_t)marker[offset]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return true;
        }
    }
    return false;
}

int32_t
cs_secret_name_looks_secret_like(const uint8_t *name, size_t name_length)
{
    static const char *const markers[] = {
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY",
        "ACCESS_KEY", "CREDENTIAL", "AUTH", "SIGNING_KEY", "ENCRYPTION_KEY",
        "COOKIE", "WEBHOOK", "DATABASE_URL", "REDIS_URL", "DSN", NULL,
    };
    if (name == NULL && name_length != 0) {
        return 0;
    }
    while (name_length > 0 && *name == '-') {
        name++;
        name_length--;
    }
    for (size_t index = 0; markers[index] != NULL; index++) {
        if (cs_name_contains_marker(name, name_length, markers[index])) {
            return 1;
        }
    }
    return 0;
}

static bool
cs_bytes_start_with(const uint8_t *value, size_t value_length,
    const char *prefix)
{
    const size_t prefix_length = strlen(prefix);
    return prefix_length <= value_length &&
        memcmp(value, prefix, prefix_length) == 0;
}

static bool
cs_bytes_contain(const uint8_t *value, size_t value_length,
    const char *needle)
{
    const size_t needle_length = strlen(needle);
    if (needle_length > value_length) {
        return false;
    }
    for (size_t start = 0; start + needle_length <= value_length; start++) {
        if (memcmp(value + start, needle, needle_length) == 0) {
            return true;
        }
    }
    return false;
}

static bool
cs_is_scheme_byte(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') ||
        byte == '+' || byte == '-' || byte == '.';
}

/*
 * Return -1 when the value is not an absolute hierarchical URL, 0 for a URL
 * without a non-empty userinfo password, and 1 for a URL carrying one. Keeping
 * this parser deliberately lexical avoids normalizing or decoding the value.
 */
static int32_t
cs_url_password_state(const uint8_t *value, size_t value_length)
{
    if (value_length < 4 ||
        !((value[0] >= 'A' && value[0] <= 'Z') ||
          (value[0] >= 'a' && value[0] <= 'z'))) {
        return -1;
    }

    size_t scheme_end = 1;
    while (scheme_end < value_length && cs_is_scheme_byte(value[scheme_end])) {
        scheme_end++;
    }
    if (scheme_end + 2 >= value_length || value[scheme_end] != ':' ||
        value[scheme_end + 1] != '/' || value[scheme_end + 2] != '/') {
        return -1;
    }
    for (size_t index = 0; index < value_length; index++) {
        if (value[index] <= 0x20 || value[index] == 0x7f) {
            return -1;
        }
    }

    const size_t authority_start = scheme_end + 3;
    size_t authority_end = authority_start;
    while (authority_end < value_length && value[authority_end] != '/' &&
           value[authority_end] != '?' && value[authority_end] != '#') {
        authority_end++;
    }

    bool has_userinfo = false;
    size_t userinfo_end = authority_start;
    for (size_t index = authority_start; index < authority_end; index++) {
        if (value[index] == '@') {
            has_userinfo = true;
            userinfo_end = index;
        }
    }
    if (!has_userinfo) {
        return 0;
    }
    for (size_t index = authority_start; index < userinfo_end; index++) {
        if (value[index] == ':') {
            return index + 1 < userinfo_end ? 1 : 0;
        }
    }
    return 0;
}

static bool
cs_is_token_byte(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') ||
        byte == '+' || byte == '/' || byte == '=' || byte == '_' ||
        byte == '-' || byte == '.' || byte == ':';
}

static bool
cs_is_hex_byte(uint8_t byte)
{
    return (byte >= '0' && byte <= '9') ||
        (byte >= 'a' && byte <= 'f') ||
        (byte >= 'A' && byte <= 'F');
}

static bool
cs_is_base64_byte(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') ||
        byte == '+' || byte == '/' || byte == '=' || byte == '_' || byte == '-';
}

static bool
cs_has_known_secret_prefix(const uint8_t *value, size_t value_length)
{
    static const char *const prefixes[] = {
        "sk-", "sk_live_", "sk_test_", "rk_live_",
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        "glpat-", "npm_", "dop_v1_", "shpat_", "shpss_",
        "AKIA", "ASIA", "AIza", "eyJ", NULL,
    };
    for (size_t index = 0; prefixes[index] != NULL; index++) {
        if (cs_bytes_start_with(value, value_length, prefixes[index])) {
            return true;
        }
    }
    return value_length >= 5 && value[0] == 'x' && value[1] == 'o' &&
        value[2] == 'x' && value[4] == '-';
}

double
cs_secret_shannon_entropy_bits_per_byte(const uint8_t *value,
    size_t value_length)
{
    if (value_length == 0 || value == NULL) {
        return 0;
    }
    size_t counts[256] = {0};
    for (size_t index = 0; index < value_length; index++) {
        counts[value[index]]++;
    }
    const double total = (double)value_length;
    double entropy = 0.0;
    for (size_t index = 0; index < 256; index++) {
        if (counts[index] == 0) {
            continue;
        }
        const double probability = (double)counts[index] / total;
        entropy -= probability * log2(probability);
    }
    return entropy;
}

int32_t
cs_secret_value_looks_secret_like(const uint8_t *value, size_t value_length)
{
    if (value == NULL && value_length != 0) {
        return 0;
    }

    const int32_t url_password_state =
        cs_url_password_state(value, value_length);
    if (url_password_state >= 0) {
        return url_password_state;
    }
    if (cs_bytes_contain(value, value_length, "-----BEGIN") &&
        cs_bytes_contain(value, value_length, "PRIVATE KEY")) {
        return 1;
    }
    if (value_length < 8) {
        return 0;
    }
    if (cs_has_known_secret_prefix(value, value_length)) {
        return 1;
    }
    if (value_length < 20) {
        return 0;
    }

    size_t token_byte_count = 0;
    bool has_letter = false;
    bool has_digit = false;
    bool all_hex = true;
    bool all_base64 = true;
    for (size_t index = 0; index < value_length; index++) {
        const uint8_t byte = value[index];
        if (byte == ' ' || byte == '\t') {
            return 0;
        }
        if (cs_is_token_byte(byte)) {
            token_byte_count++;
        }
        has_letter = has_letter ||
            (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
        has_digit = has_digit || (byte >= '0' && byte <= '9');
        all_hex = all_hex && cs_is_hex_byte(byte);
        all_base64 = all_base64 && cs_is_base64_byte(byte);
    }
    if ((double)token_byte_count < 0.9 * (double)value_length) {
        return 0;
    }
    if (value_length >= 32 && all_hex) {
        return 1;
    }
    if (!has_letter || !has_digit) {
        return 0;
    }
    if (value_length >= 24 && all_base64) {
        return 1;
    }
    return cs_secret_shannon_entropy_bits_per_byte(value, value_length) >= 3.5;
}
