#include <assert.h>
#include <string.h>
#include "../vulnerable/parser.h"

int main(void) {
    unsigned char packet[] = {4, 'a', 'b', 'c', 'd'};
    char out[16];
    int n = parse_packet(packet, sizeof(packet), out, sizeof(out));
    assert(n == 4);
    assert(memcmp(out, "abcd", 4) == 0);

    unsigned char malformed[] = {9, 'x'};
    int rc = parse_packet(malformed, sizeof(malformed), out, sizeof(out));
    assert(rc == -1);

    return 0;
}
