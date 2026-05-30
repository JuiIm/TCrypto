/*
 * bmp_io.h — Load/save 24-bit BMP images for pixel-level analysis.
 * Handles BGR<->RGB conversion and row padding automatically.
 */
#ifndef BMP_IO_H
#define BMP_IO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	int width;
	int height;
	int channels;
	uint8_t *data;
} bmp_image_t;

int bmp_load(const char *path, bmp_image_t *img);

int bmp_save(const char *path, const bmp_image_t *img);

void bmp_free(bmp_image_t *img);

#endif /* BMP_IO_H */
