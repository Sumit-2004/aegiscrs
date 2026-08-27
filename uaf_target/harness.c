#include <stdint.h>
#include <stddef.h>
#include "vulnerable/session.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    process_session(data, size);
    return 0;
}
