#include "bignum.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

double get_time_ms()
{
	LARGE_INTEGER freq, now;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&now);

	return (double)now.QuadPart * 1000.0 / (double)freq.QuadPart;
}

int main(void)
{
	printf("Generating keys...\n");
	rsa_key_t key;
	if (rsa_keygen(&key, 512) != 0) {
		fprintf(stderr, "Key generation failed\n");
		return 1;
	}
	printf("Keys generated.\n");

	/* Reading Colored_butterfly.png from .. */

	FILE *fp =
	    fopen("C:\\Users\\Codename\\Documents\\code\\TCryptoNew\\Colored_"
		  "butterfly.png",
		  "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open file\n");
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	size_t file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	uint8_t *pixels = (uint8_t *)malloc(file_size);
	if (!pixels) {
		fprintf(stderr, "Failed to allocate memory\n");
		return 1;
	}
	if (fread(pixels, 1, file_size, fp) != file_size) {
		fprintf(stderr, "Failed to read file\n");
		return 1;
	}

	printf("Done reading file.\n");

	fclose(fp);

	double enc_start = get_time_ms();
	printf("Encrypting image...\n");
	size_t out_len;
	uint8_t *cipher = rsa_encrypt_image(pixels, file_size, &key, &out_len);
	if (!cipher) {
		fprintf(stderr, "Failed to encrypt image\n");
		return 1;
	}

	double enc_end = get_time_ms();

	printf("Done encrypting image in %.2f ms.\n", enc_end - enc_start);

	printf("Decrypting image...\n");

	double dec_start = get_time_ms();

	size_t dec_len;
	uint8_t *decrypted = rsa_decrypt_image(cipher, out_len, &key, &dec_len);
	if (!decrypted) {
		fprintf(stderr, "Failed to decrypt image\n");
		return 1;
	}

	double dec_end = get_time_ms();

	printf("Done decrypting image in %.2f ms.\n", dec_end - dec_start);

	printf("Writing encrypted file...\n");
	FILE *out_fp =
	    fopen("C:\\Users\\Codename\\Documents\\code\\TCryptoNew\\Colored_"
		  "butterfly_encrypted.bin",
		  "wb");
	if (!out_fp) {
		fprintf(stderr, "Failed to open file\n");
		return 1;
	}
	fwrite(cipher, 1, out_len, out_fp);
	fclose(out_fp);
	printf("Done writing encrypted file.\n");

	printf("Writing decrypted file...\n");
	FILE *dec_fp =
	    fopen("C:\\Users\\Codename\\Documents\\code\\TCryptoNew\\Colored_"
		  "butterfly_decrypted.png",
		  "wb");
	if (!dec_fp) {
		fprintf(stderr, "Failed to open file\n");
		return 1;
	}
	fwrite(decrypted, 1, dec_len, dec_fp);
	fclose(dec_fp);

	/* Cleaning up */
	free(pixels);
	free(cipher);
	free(decrypted);

	return 0;
}