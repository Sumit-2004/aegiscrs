#include <stdint.h>
#include <stddef.h>
#include "vulnerable/parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char out[16];
    parse_packet(data, size, out, sizeof(out));
    return 0;
}
