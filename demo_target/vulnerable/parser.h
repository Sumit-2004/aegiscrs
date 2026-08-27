#ifndef PARSER_H
#define PARSER_H

#include <stddef.h>

/* Packet format: byte 0 is payload length, bytes 1..len are the payload.
   Returns the number of bytes copied into out, or -1 on a malformed packet. */
int parse_packet(const unsigned char *data, size_t size, char *out, size_t out_cap);

#endif
