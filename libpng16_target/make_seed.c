/* One-off generator for the CVE-2025-64505 seed corpus file: a valid,
 * well-formed 8x8 PNG with color_type=PALETTE and a 2-entry PLTE, but whose
 * raw IDAT pixel bytes are all 0xC8 (200) - a "malformed" but
 * spec-permitted palette index far outside the declared 2-color palette.
 * Written with this exact libpng build so the file is guaranteed
 * structurally valid (correct CRCs, zlib-compressed IDAT) rather than
 * hand-crafted bytes. Not part of the fuzz target itself - run once to
 * produce seed_corpus/small_palette.png.
 */
#include <png.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  FILE *fp = fopen("seed_corpus/small_palette.png", "wb");
  if (!fp) { perror("fopen"); return 1; }

  png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
  png_infop info = png_create_info_struct(png);
  png_init_io(png, fp);

  const int width = 8, height = 8;
  png_set_IHDR(png, info, width, height, 8, PNG_COLOR_TYPE_PALETTE,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  /* libpng's own write path rejects a pixel index >= num_palette, so we
   * can't write the malformed file directly. Write with a full 256-entry
   * palette here (making index 200 legal); shrink_plte.py then truncates
   * the on-disk PLTE chunk to 2 entries afterward, leaving the IDAT bytes
   * (and their index-200 pixels) untouched - producing the exact malformed
   * "index >= num_palette" shape CVE-2025-64505 needs.
   */
  png_color palette[256];
  for (int i = 0; i < 256; i++) {
    palette[i].red = palette[i].green = palette[i].blue = (png_byte)i;
  }
  png_set_PLTE(png, info, palette, 256);

  png_write_info(png, info);

  /* Raw pixel bytes: index 200, valid PNG bitstream-wise (any byte 0-255 is
   * legal in an 8-bit palette row), but way out of range for the 2-entry
   * palette actually declared above.
   */
  png_bytep row = (png_bytep)malloc(width);
  memset(row, 200, width);
  for (int y = 0; y < height; y++)
    png_write_row(png, row);
  png_write_end(png, NULL);

  png_destroy_write_struct(&png, &info);
  free(row);
  fclose(fp);
  return 0;
}
