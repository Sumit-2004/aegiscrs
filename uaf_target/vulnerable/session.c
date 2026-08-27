#include "session.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    char buf[32];
} Session;

void process_session(const unsigned char *data, size_t size) {
    Session *s = NULL;
    size_t i = 0;

    while (i < size) {
        unsigned char op = data[i++];

        if (op == 0) {
            if (s != NULL) {
                free(s);
            }
            s = malloc(sizeof(Session));
            if (s != NULL) {
                memset(s->buf, 0, sizeof(s->buf));
            }
        } else if (op == 1) {
            free(s);
            /* BUG: s is left dangling instead of being reset to NULL, so the
               s != NULL guard below still passes after this point. */
        } else if (op == 2) {
            if (i >= size) break;
            unsigned char len = data[i++];
            size_t remaining = size - i;
            size_t n = len;
            if (n > remaining) n = remaining;
            if (n > sizeof(s->buf)) n = sizeof(s->buf);
            if (s != NULL) {
                memcpy(s->buf, data + i, n);
            }
            i += n;
        }
    }
}
