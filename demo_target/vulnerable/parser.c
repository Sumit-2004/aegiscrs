#include "parser.h"
#include <string.h>

int parse_packet(const unsigned char *data, size_t size, char *out, size_t out_cap) {
    if (size < 1) {
        return -1;
    }
    unsigned char len = data[0];
    if (size < (size_t)len + 1) {
        return -1;
    }
    memcpy(out, data + 1, len);
    return (int)len;
}
