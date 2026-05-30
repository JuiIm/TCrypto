/*
 * bmp_io.c — Read/write 24-bit BMP files.
 * Converts BGR (BMP native) <-> RGB on load/save.
 * Row stride is padded to 4-byte boundary per BMP spec.
 */
#include "bmp_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
	uint16_t type; /* 'BM' */
	uint32_t file_size;
	uint16_t reserved1;
	uint16_t reserved2;
	uint32_t offset; /* offset to pixel data */
} bmp_file_header_t;

typedef struct {
	uint32_t header_size; /* 40 */
	int32_t width;
	int32_t height;	      /* positive = bottom-up, negative = top-down */
	uint16_t planes;      /* 1 */
	uint16_t bpp;	      /* 24 */
	uint32_t compression; /* 0 = none */
	uint32_t image_size;
	int32_t x_ppm;
	int32_t y_ppm;
	uint32_t colors_used;
	uint32_t colors_important;
} bmp_info_header_t;
#pragma pack(pop)

int bmp_load(const char *path, bmp_image_t *img)
{
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "bmp_load: cannot open %s\n", path);
		return -1;
	}

	bmp_file_header_t fh;
	bmp_info_header_t ih;

	fread(&fh, sizeof(fh), 1, fp);
	fread(&ih, sizeof(ih), 1, fp);

	if (fh.type != 0x4D42) { /* 'BM' */
		fprintf(stderr, "bmp_load: not a BMP file\n");
		fclose(fp);
		return -1;
	}

	if (ih.bpp != 24) {
		fprintf(stderr, "bmp_load: only 24-bit BMP supported\n");
		fclose(fp);
		return -1;
	}

	img->width = ih.width;
	img->height = abs(ih.height);
	img->channels = 3;

	int row_stride = (img->width * 3 + 3) & ~3;
	size_t pixel_count = (size_t)img->width * img->height * 3;
	img->data = (uint8_t *)malloc(pixel_count);
	if (!img->data) {
		fclose(fp);
		return -1;
	}

	fseek(fp, fh.offset, SEEK_SET);

	uint8_t *row_buf = (uint8_t *)malloc(row_stride);
	int bottom_up = (ih.height > 0);

	for (int y = 0; y < img->height; y++) {
		int dst_y = bottom_up ? (img->height - 1 - y) : y;
		fread(row_buf, 1, row_stride, fp);

		/* BMP stores BGR, convert to RGB */
		for (int x = 0; x < img->width; x++) {
			int si = x * 3;
			int di = (dst_y * img->width + x) * 3;
			img->data[di + 0] = row_buf[si + 2]; /* R */
			img->data[di + 1] = row_buf[si + 1]; /* G */
			img->data[di + 2] = row_buf[si + 0]; /* B */
		}
	}

	free(row_buf);
	fclose(fp);
	return 0;
}

int bmp_save(const char *path, const bmp_image_t *img)
{
	int row_stride = (img->width * 3 + 3) & ~3;
	uint32_t pixel_data_size = (uint32_t)(row_stride * img->height);

	bmp_file_header_t fh = {0};
	fh.type = 0x4D42;
	fh.offset = sizeof(bmp_file_header_t) + sizeof(bmp_info_header_t);
	fh.file_size = fh.offset + pixel_data_size;

	bmp_info_header_t ih = {0};
	ih.header_size = sizeof(bmp_info_header_t);
	ih.width = img->width;
	ih.height = img->height; /* bottom-up */
	ih.planes = 1;
	ih.bpp = 24;
	ih.image_size = pixel_data_size;

	FILE *fp = fopen(path, "wb");
	if (!fp) {
		fprintf(stderr, "bmp_save: cannot open %s\n", path);
		return -1;
	}

	fwrite(&fh, sizeof(fh), 1, fp);
	fwrite(&ih, sizeof(ih), 1, fp);

	uint8_t *row_buf = (uint8_t *)calloc(1, row_stride);

	for (int y = img->height - 1; y >= 0; y--) {
		/* Convert RGB to BGR for BMP */
		for (int x = 0; x < img->width; x++) {
			int si = (y * img->width + x) * 3;
			int di = x * 3;
			row_buf[di + 0] = img->data[si + 2]; /* B */
			row_buf[di + 1] = img->data[si + 1]; /* G */
			row_buf[di + 2] = img->data[si + 0]; /* R */
		}
		fwrite(row_buf, 1, row_stride, fp);
	}

	free(row_buf);
	fclose(fp);
	return 0;
}

void bmp_free(bmp_image_t *img)
{
	if (img->data) {
		free(img->data);
		img->data = NULL;
	}
}
