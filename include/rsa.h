#ifndef RSA_H
#define RSA_H

#include "bignum.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
	bignum_t n;    /* Modulus: n = p * q                */
	bignum_t e;    /* Public exponent (e)               */
	bignum_t d;    /* Private exponent                  */
	bignum_t p;    /* First prime factor                */
	bignum_t q;    /* Second prime factor               */
	bignum_t dp;   /* d mod (p-1) for CRT               */
	bignum_t dq;   /* d mod (q-1) for CRT               */
	bignum_t qinv; /* q^(-1) mod p for CRT              */
	int bits;      /* Key size in bits                  */
} rsa_key_t;

#define RSA_KEY_BYTES(key) (((key)->bits + 7) / 8)

#define RSA_RAW_BLOCK_SIZE(key) (RSA_KEY_BYTES(key) - 1)

int rsa_keygen(rsa_key_t *key, int bits);

void rsa_print_key(const rsa_key_t *key);

void rsa_encrypt_block(bignum_t *c, const bignum_t *m, const rsa_key_t *key);

void rsa_decrypt_block(bignum_t *m, const bignum_t *c, const rsa_key_t *key);

uint8_t *rsa_encrypt_image(const uint8_t *pixels, size_t pix_len,
			   const rsa_key_t *key, size_t *out_len);

uint8_t *rsa_decrypt_image(const uint8_t *cipher, size_t cip_len,
			   const rsa_key_t *key, size_t *out_len);

/* RSA + OAEP (Task 2) */

uint8_t *rsa_oaep_encrypt_image(const uint8_t *pixels, size_t pix_len,
				const rsa_key_t *key, size_t *out_len);

uint8_t *rsa_oaep_decrypt_image(const uint8_t *cipher, size_t cip_len,
				const rsa_key_t *key, size_t *out_len);

/*
 * Build an RSA key from known hex-encoded primes and exponent.
 * Computes n, d, dp, dq, qinv automatically.
 * Returns 0 on success, -1 on error.
 */
int rsa_key_from_hex(rsa_key_t *key, const char *p_hex, const char *q_hex,
		     const char *e_hex);

#endif /* RSA_H */
