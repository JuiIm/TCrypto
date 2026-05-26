#include "bignum.h"
#include "oaep.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define BASE_PATH "C:\\Users\\Codename\\Documents\\code\\TCryptoNew\\"
#define INPUT_FILE BASE_PATH "Colored_butterfly.png"

double get_time_ms()
{
	LARGE_INTEGER freq, now;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&now);
	return (double)now.QuadPart * 1000.0 / (double)freq.QuadPart;
}

uint8_t *read_file(const char *path, size_t *len)
{
	FILE *fp = fopen(path, "rb");
	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	*len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint8_t *buf = (uint8_t *)malloc(*len);
	if (buf)
		fread(buf, 1, *len, fp);
	fclose(fp);
	return buf;
}

int write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *fp = fopen(path, "wb");
	if (!fp)
		return -1;
	fwrite(data, 1, len, fp);
	fclose(fp);
	return 0;
}

int main(void)
{
	size_t file_size;
	uint8_t *pixels = read_file(INPUT_FILE, &file_size);
	if (!pixels) {
		fprintf(stderr, "Failed to open %s\n", INPUT_FILE);
		return 1;
	}
	printf("Read %zu bytes from input image.\n", file_size);

	printf("\nGenerating 512-bit RSA key...\n");
	rsa_key_t key;
	if (rsa_keygen(&key, 1024) != 0) {
		fprintf(stderr, "Key generation failed\n");
		return 1;
	}
	printf("Key generated (%d-bit modulus).\n", key.bits);

	/* ── Task 1: Raw RSA ────────────────────────────── */
	printf("\n=== Task 1: Raw RSA ===\n");
	{
		double t0 = get_time_ms();
		size_t enc_len;
		uint8_t *enc =
		    rsa_encrypt_image(pixels, file_size, &key, &enc_len);
		double t1 = get_time_ms();
		printf("  Encrypt: %.2f ms (%zu bytes)\n", t1 - t0, enc_len);

		double t2 = get_time_ms();
		size_t dec_len;
		uint8_t *dec = rsa_decrypt_image(enc, enc_len, &key, &dec_len);
		double t3 = get_time_ms();
		printf("  Decrypt: %.2f ms (%zu bytes)\n", t3 - t2, dec_len);

		int match = (dec_len >= file_size) &&
			    (memcmp(pixels, dec, file_size) == 0);
		printf("  Roundtrip: %s\n", match ? "OK" : "MISMATCH");

		write_file(BASE_PATH "raw_encrypted.bin", enc, enc_len);
		write_file(BASE_PATH "raw_decrypted.png", dec, dec_len);

		free(enc);
		free(dec);
	}

	/* ── Task 2: RSA + OAEP ─────────────────────────── */
	printf("\n=== Task 2: RSA + OAEP ===\n");
	{
		double t0 = get_time_ms();
		size_t enc_len;
		uint8_t *enc =
		    rsa_oaep_encrypt_image(pixels, file_size, &key, &enc_len);
		double t1 = get_time_ms();
		if (!enc) {
			fprintf(stderr, "  OAEP encrypt failed\n");
			free(pixels);
			return 1;
		}
		printf("  Encrypt: %.2f ms (%zu bytes)\n", t1 - t0, enc_len);

		double t2 = get_time_ms();
		size_t dec_len;
		uint8_t *dec =
		    rsa_oaep_decrypt_image(enc, enc_len, &key, &dec_len);
		double t3 = get_time_ms();
		if (!dec) {
			fprintf(stderr, "  OAEP decrypt failed\n");
			free(enc);
			free(pixels);
			return 1;
		}
		printf("  Decrypt: %.2f ms (%zu bytes)\n", t3 - t2, dec_len);

		int match = (dec_len == file_size) &&
			    (memcmp(pixels, dec, file_size) == 0);
		printf("  Roundtrip: %s\n", match ? "OK" : "MISMATCH");

		write_file(BASE_PATH "oaep_encrypted.bin", enc, enc_len);
		write_file(BASE_PATH "oaep_decrypted.png", dec, dec_len);

		free(enc);
		free(dec);
	}

	free(pixels);
	printf("\nDone.\n");
	return 0;
}