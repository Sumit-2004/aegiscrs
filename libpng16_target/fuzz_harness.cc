// Fuzz harness for CVE-2025-64505: heap buffer over-read in png_do_quantize
// (pngrtran.c) via a malformed palette index. png_set_quantize(..., 0) [not
// full_quantize] allocates quantize_index with only num_palette bytes, but
// png_do_quantize's pixel loop indexes it with the RAW pixel byte from the
// PNG's own IDAT data ("*sp = quantize_lookup[*sp];"), which for a
// PNG_COLOR_TYPE_PALETTE image can be any value 0-255 regardless of how
// small the actual PLTE chunk declared. A file with a 2-entry palette and a
// pixel byte of, say, 200 reads far past the 2-byte allocation. Fixed
// upstream in libpng 1.6.51 by always allocating 256 (PNG_MAX_PALETTE_LENGTH)
// bytes for quantize_index regardless of num_palette.
#include <png.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

namespace {
struct MemReader {
  const uint8_t *data;
  size_t size;
  size_t pos;
};

void mem_read(png_structp png_ptr, png_bytep out, size_t n) {
  MemReader *r = static_cast<MemReader *>(png_get_io_ptr(png_ptr));
  if (r->pos + n > r->size) {
    png_error(png_ptr, "eof");
    return;
  }
  memcpy(out, r->data + r->pos, n);
  r->pos += n;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;

  png_structp png_ptr =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    return 0;
  }

  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    return 0;
  }

  MemReader reader{data, size, 0};
  png_set_read_fn(png_ptr, &reader, mem_read);
  png_read_info(png_ptr, info_ptr);

  png_colorp palette = nullptr;
  int num_palette = 0;
  if (png_get_color_type(png_ptr, info_ptr) == PNG_COLOR_TYPE_PALETTE &&
      png_get_PLTE(png_ptr, info_ptr, &palette, &num_palette) != 0 &&
      num_palette > 0) {
    // full_quantize=0: the identity-map path that under-allocates
    // quantize_index to num_palette bytes instead of 256.
    png_set_quantize(png_ptr, palette, num_palette, num_palette, nullptr, 0);
  }

  png_read_update_info(png_ptr, info_ptr);

  png_uint_32 width = png_get_image_width(png_ptr, info_ptr);
  png_uint_32 height = png_get_image_height(png_ptr, info_ptr);
  if (width == 0 || height == 0 || height > 4096) {
    png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    return 0;
  }

  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  std::vector<unsigned char> buf(rowbytes * height);
  std::vector<png_bytep> rows(height);
  for (png_uint_32 y = 0; y < height; y++)
    rows[y] = buf.data() + static_cast<size_t>(y) * rowbytes;

  png_read_image(png_ptr, rows.data());

  png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
  return 0;
}
