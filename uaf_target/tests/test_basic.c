#include <assert.h>
#include <stdio.h>
#include "../vulnerable/session.h"

int main(void) {
    /* open, write(2 bytes), open-again (frees+reallocates cleanly),
       write(1 byte), close - no reuse after the close, so this must never
       touch freed memory or leak the final allocation. */
    unsigned char normal[] = {0, 2, 2, 'h', 'i', 0, 2, 1, 'x', 1};
    process_session(normal, sizeof(normal));

    /* open then close with no further use - must not crash either. */
    unsigned char close_only[] = {0, 1};
    process_session(close_only, sizeof(close_only));

    printf("ok\n");
    return 0;
}
