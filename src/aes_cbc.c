#include "aes_cbc.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int aes_cbc_encrypt(const uint8_t *pt, size_t pt_len, const uint8_t *key,
		    const uint8_t *iv, uint8_t *ct, size_t *ct_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int out_len = 0;
	if (EVP_EncryptUpdate(ctx, ct, &out_len, pt, (int)pt_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	int total = out_len;

	if (EVP_EncryptFinal_ex(ctx, ct + total, &out_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	total += out_len;

	*ct_len = (size_t)total;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int aes_cbc_decrypt(const uint8_t *ct, size_t ct_len, const uint8_t *key,
		    const uint8_t *iv, uint8_t *pt, size_t *pt_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	int out_len = 0;
	if (EVP_DecryptUpdate(ctx, pt, &out_len, ct, (int)ct_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	int total = out_len;

	if (EVP_DecryptFinal_ex(ctx, pt + total, &out_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	total += out_len;

	*pt_len = (size_t)total;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

void aes_generate_key_iv(uint8_t key[AES_KEY_SIZE], uint8_t iv[AES_IV_SIZE])
{
	RAND_bytes(key, AES_KEY_SIZE);
	RAND_bytes(iv, AES_IV_SIZE);
}
