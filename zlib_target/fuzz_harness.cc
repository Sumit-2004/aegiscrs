// Fuzz harness for CVE-2022-37434 (heap buffer over-read in inflate.c's
// gzip-header EXTRA field handling, zlib < 1.2.12). Feeds input one byte at
// a time to inflate() - matching how a chunked network/file read would
// deliver a gzip stream in practice - so the incremental extra-field length
// accumulation in inflate.c can walk past head.extra_max the same way it
// would for a real caller using inflateGetHeader() on untrusted input.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "zlib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, 15 + 16) != Z_OK)  // 15+16: gzip-only, 32K window
        return 0;

    gz_header header;
    memset(&header, 0, sizeof(header));
    unsigned char extra_buf[16];
    header.extra = extra_buf;
    header.extra_max = sizeof(extra_buf);

    if (inflateGetHeader(&strm, &header) != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    unsigned char out[256];
    for (size_t i = 0; i < size; i++) {
        strm.next_in = const_cast<Bytef*>(data + i);
        strm.avail_in = 1;
        do {
            strm.next_out = out;
            strm.avail_out = sizeof(out);
            int ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_END || ret == Z_DATA_ERROR ||
                ret == Z_MEM_ERROR || ret == Z_NEED_DICT || ret < 0) {
                inflateEnd(&strm);
                return 0;
            }
        } while (strm.avail_out == 0);
    }

    inflateEnd(&strm);
    return 0;
}
