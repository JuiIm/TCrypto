/*
 * main.c — Benchmark runner for all three encryption tasks.
 *
 * Runs Task 1 (Raw RSA), Task 2 (RSA+OAEP), and Task 3 (Hybrid AES)
 * on both PNG file bytes and BMP raw pixels. Outputs timing to
 * performance.csv and encrypted BMP images for security analysis.
 *
 * Run with: make run
 */
#include "aes_cbc.h"
#include "bignum.h"
#include "bmp_io.h"
#include "oaep.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define BASE_PATH "C:\\Users\\Codename\\Documents\\code\\TCryptoNew\\"
#define PNG_FILE BASE_PATH "Black_and_white_butterfly.png"
#define BMP_FILE BASE_PATH "Black_and_white_butterfly.bmp"
#define OUTPUT_DIR BASE_PATH "output\\"

static double get_time_ms(void)
{
	LARGE_INTEGER freq, now;
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&now);
	return (double)now.QuadPart * 1000.0 / (double)freq.QuadPart;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *fp = fopen(path, "wb");
	if (!fp)
		return -1;
	fwrite(data, 1, len, fp);
	fclose(fp);
	return 0;
}

static uint8_t *read_file(const char *path, size_t *len)
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

static void save_encrypted_bmp(const char *path, const uint8_t *data,
			       size_t data_len, int w, int h)
{
	size_t pix_cnt = (size_t)w * h * 3;
	bmp_image_t enc_img = {w, h, 3, (uint8_t *)malloc(pix_cnt)};
	for (size_t i = 0; i < pix_cnt; i++)
		enc_img.data[i] = (i < data_len) ? data[i] : 0;
	bmp_save(path, &enc_img);
	free(enc_img.data);
}

static void run_all_tasks(const uint8_t *data, size_t data_len,
			  const rsa_key_t *key, FILE *csv, const char *prefix,
			  int bmp_w, int bmp_h)
{
	int is_bmp = (bmp_w > 0 && bmp_h > 0);

	printf("\n  --- Task 1: Raw RSA ---\n");
	{
		double t0 = get_time_ms();
		size_t enc_len;
		uint8_t *enc = rsa_encrypt_image(data, data_len, key, &enc_len);
		double t1 = get_time_ms();
		double enc_ms = t1 - t0;
		printf("    Encrypt: %.2f ms (%zu bytes)\n", enc_ms, enc_len);

		double t2 = get_time_ms();
		size_t dec_len;
		uint8_t *dec = rsa_decrypt_image(enc, enc_len, key, &dec_len);
		double t3 = get_time_ms();
		double dec_ms = t3 - t2;
		printf("    Decrypt: %.2f ms (%zu bytes)\n", dec_ms, dec_len);

		int ok =
		    (dec_len == data_len) && (memcmp(data, dec, data_len) == 0);
		printf("    Roundtrip: %s\n", ok ? "OK" : "MISMATCH");

		char path[512];
		snprintf(path, sizeof(path),
			 OUTPUT_DIR "%s_task1_encrypted.bin", prefix);
		write_file(path, enc, enc_len);

		if (is_bmp) {
			snprintf(path, sizeof(path),
				 OUTPUT_DIR "%s_task1_encrypted.bmp", prefix);
			save_encrypted_bmp(path, enc, enc_len, bmp_w, bmp_h);

			snprintf(path, sizeof(path),
				 OUTPUT_DIR "%s_task1_decrypted.bmp", prefix);
			bmp_image_t dec_img = {bmp_w, bmp_h, 3, dec};
			bmp_save(path, &dec_img);
		}

		fprintf(csv, "%s_task1,encrypt,%.2f,%zu,%d\n", prefix, enc_ms,
			data_len, key->bits);
		fprintf(csv, "%s_task1,decrypt,%.2f,%zu,%d\n", prefix, dec_ms,
			data_len, key->bits);

		free(enc);
		free(dec);
	}

	printf("\n  --- Task 2: RSA + OAEP ---\n");
	{
		double t0 = get_time_ms();
		size_t enc_len;
		uint8_t *enc =
		    rsa_oaep_encrypt_image(data, data_len, key, &enc_len);
		double t1 = get_time_ms();
		double enc_ms = t1 - t0;
		if (!enc) {
			printf("    OAEP encrypt failed!\n");
			return;
		}
		printf("    Encrypt: %.2f ms (%zu bytes)\n", enc_ms, enc_len);

		double t2 = get_time_ms();
		size_t dec_len;
		uint8_t *dec =
		    rsa_oaep_decrypt_image(enc, enc_len, key, &dec_len);
		double t3 = get_time_ms();
		double dec_ms = t3 - t2;
		if (!dec) {
			printf("    OAEP decrypt failed!\n");
			free(enc);
			return;
		}
		printf("    Decrypt: %.2f ms (%zu bytes)\n", dec_ms, dec_len);

		int ok =
		    (dec_len == data_len) && (memcmp(data, dec, data_len) == 0);
		printf("    Roundtrip: %s\n", ok ? "OK" : "MISMATCH");

		char path[512];
		snprintf(path, sizeof(path),
			 OUTPUT_DIR "%s_task2_encrypted.bin", prefix);
		write_file(path, enc, enc_len);

		if (is_bmp) {
			snprintf(path, sizeof(path),
				 OUTPUT_DIR "%s_task2_encrypted.bmp", prefix);
			save_encrypted_bmp(path, enc, enc_len, bmp_w, bmp_h);

			snprintf(path, sizeof(path),
				 OUTPUT_DIR "%s_task2_decrypted.bmp", prefix);
			bmp_image_t dec_img = {bmp_w, bmp_h, 3, dec};
			bmp_save(path, &dec_img);
		}

		fprintf(csv, "%s_task2,encrypt,%.2f,%zu,%d\n", prefix, enc_ms,
			data_len, key->bits);
		fprintf(csv, "%s_task2,decrypt,%.2f,%zu,%d\n", prefix, dec_ms,
			data_len, key->bits);

		free(enc);
		free(dec);
	}

	printf("\n  --- Task 3: Hybrid (RSA+OAEP + AES-256-CBC) ---\n");
	{
		uint8_t aes_key[AES_KEY_SIZE], aes_iv[AES_IV_SIZE];
		aes_generate_key_iv(aes_key, aes_iv);
		int rsa_k = RSA_KEY_BYTES(key);

		double t0 = get_time_ms();

		uint8_t em[512], enc_aes_key[512];
		oaep_encode(aes_key, AES_KEY_SIZE, rsa_k, em);
		bignum_t m_key, c_key;
		bn_init(&m_key);
		bn_init(&c_key);
		bn_from_bytes(&m_key, em, rsa_k);
		rsa_encrypt_block(&c_key, &m_key, key);
		bn_to_bytes(&c_key, enc_aes_key, rsa_k);

		size_t aes_ct_len;
		uint8_t *aes_ct = (uint8_t *)malloc(data_len + AES_BLOCK_SIZE);
		aes_cbc_encrypt(data, data_len, aes_key, aes_iv, aes_ct,
				&aes_ct_len);

		double t1 = get_time_ms();
		double enc_ms = t1 - t0;

		size_t hybrid_len = rsa_k + AES_IV_SIZE + aes_ct_len;
		uint8_t *hybrid = (uint8_t *)malloc(hybrid_len);
		memcpy(hybrid, enc_aes_key, rsa_k);
		memcpy(hybrid + rsa_k, aes_iv, AES_IV_SIZE);
		memcpy(hybrid + rsa_k + AES_IV_SIZE, aes_ct, aes_ct_len);

		printf("    Encrypt: %.2f ms (%zu bytes)\n", enc_ms,
		       hybrid_len);

		char path[512];
		snprintf(path, sizeof(path),
			 OUTPUT_DIR "%s_task3_encrypted.bin", prefix);
		write_file(path, hybrid, hybrid_len);

		if (is_bmp) {
			snprintf(path, sizeof(path),
				 OUTPUT_DIR "%s_task3_encrypted.bmp", prefix);
			save_encrypted_bmp(path, hybrid + rsa_k + AES_IV_SIZE,
					   aes_ct_len, bmp_w, bmp_h);
		}

		double t2 = get_time_ms();

		bignum_t c_dec, m_dec;
		bn_init(&c_dec);
		bn_init(&m_dec);
		bn_from_bytes(&c_dec, hybrid, rsa_k);
		rsa_decrypt_block(&m_dec, &c_dec, key);
		uint8_t dec_em[512];
		bn_to_bytes(&m_dec, dec_em, rsa_k);

		uint8_t recovered_key[AES_KEY_SIZE];
		size_t rk_len;
		oaep_decode(dec_em, rsa_k, recovered_key, &rk_len);

		const uint8_t *rec_iv = hybrid + rsa_k;
		const uint8_t *rec_ct = hybrid + rsa_k + AES_IV_SIZE;
		size_t rec_ct_len = hybrid_len - rsa_k - AES_IV_SIZE;

		uint8_t *dec = (uint8_t *)malloc(rec_ct_len);
		size_t dec_len;
		aes_cbc_decrypt(rec_ct, rec_ct_len, recovered_key, rec_iv, dec,
				&dec_len);

		double t3 = get_time_ms();
		double dec_ms = t3 - t2;
		printf("    Decrypt: %.2f ms (%zu bytes)\n", dec_ms, dec_len);

		int ok =
		    (dec_len == data_len) && (memcmp(data, dec, data_len) == 0);
		printf("    Roundtrip: %s\n", ok ? "OK" : "MISMATCH");

		if (is_bmp) {
			snprintf(path, sizeof(path),
				 OUTPUT_DIR "%s_task3_decrypted.bmp", prefix);
			bmp_image_t dec_img = {bmp_w, bmp_h, 3, dec};
			bmp_save(path, &dec_img);
		}

		fprintf(csv, "%s_task3,encrypt,%.2f,%zu,%d\n", prefix, enc_ms,
			data_len, key->bits);
		fprintf(csv, "%s_task3,decrypt,%.2f,%zu,%d\n", prefix, dec_ms,
			data_len, key->bits);

		free(aes_ct);
		free(hybrid);
		free(dec);
	}
}

int main(void)
{
	CreateDirectoryA(OUTPUT_DIR, NULL);

	printf("Generating RSA key...\n");
	rsa_key_t key;
	if (rsa_keygen(&key, 1024) != 0) {
		fprintf(stderr, "Key generation failed\n");
		return 1;
	}
	printf("Key generated (%d-bit modulus).\n", key.bits);

	FILE *csv = fopen(OUTPUT_DIR "performance.csv", "w");
	fprintf(csv, "task,operation,time_ms,data_size_bytes,key_bits\n");

	printf("\n========================================\n");
	printf("  Phase A: PNG file (%s)\n", PNG_FILE);
	printf("========================================\n");
	{
		size_t png_len;
		uint8_t *png_data = read_file(PNG_FILE, &png_len);
		if (!png_data) {
			fprintf(stderr, "Failed to load PNG\n");
			return 1;
		}
		printf("Loaded PNG: %zu bytes\n", png_len);

		run_all_tasks(png_data, png_len, &key, csv, "png", 0, 0);
		free(png_data);
	}

	printf("\n========================================\n");
	printf("  Phase B: BMP pixels (%s)\n", BMP_FILE);
	printf("========================================\n");
	{
		bmp_image_t img;
		if (bmp_load(BMP_FILE, &img) != 0) {
			fprintf(stderr, "Failed to load BMP\n");
			return 1;
		}
		size_t pixel_count = (size_t)img.width * img.height * 3;
		printf("Loaded BMP: %dx%d (%zu bytes of pixel data)\n",
		       img.width, img.height, pixel_count);

		bmp_save(OUTPUT_DIR "original.bmp", &img);

		run_all_tasks(img.data, pixel_count, &key, csv, "bmp",
			      img.width, img.height);
		bmp_free(&img);
	}

	fclose(csv);
	printf("\n========================================\n");
	printf("All done. Results in %s\n", OUTPUT_DIR);
	printf("Run: python scripts/analyze.py\n");
	return 0;
}