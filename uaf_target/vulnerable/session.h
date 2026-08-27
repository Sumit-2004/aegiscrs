#ifndef SESSION_H
#define SESSION_H

#include <stddef.h>

/* Tiny session protocol: a sequence of opcodes read from `data`.
   0 = open a session (allocates). 1 = close it (frees). 2 <len> <payload> =
   write <len> bytes of <payload> into the session buffer. Processes every
   opcode in `data` before returning. */
void process_session(const unsigned char *data, size_t size);

#endif
