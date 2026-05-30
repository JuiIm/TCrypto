#include "rsa.h"
#include "bignum.h"
#include "oaep.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rsa_keygen(rsa_key_t *key, int bits)
{
	// if (bits < 512) {
	// 	fprintf(stderr,
	// 		"rsa_keygen: key size must be at least 512 bits\n");
	// 	return -1;
	// }

	bn_init(&key->p);
	bn_init(&key->q);
	bn_init(&key->n);
	bn_init(&key->e);
	bn_init(&key->d);
	bn_init(&key->dp);
	bn_init(&key->dq);
	bn_init(&key->qinv);

	bignum_t phi, p1, q1, gcd;

	bn_init(&phi);
	bn_init(&p1);
	bn_init(&q1);
	bn_init(&gcd);

	int half = bits / 2;

	do {
		bn_gen_prime(&key->p, half);
		bn_gen_prime(&key->q, half);
	} while (bn_cmp(&key->p, &key->q) == 0);

	bn_mul(&key->n, &key->p, &key->q);

	key->bits = bn_bit_len(&key->n);

	bn_set_word(&p1, 1);
	bn_set_word(&q1, 1);

	bn_sub(&p1, &key->p, &p1);
	bn_sub(&q1, &key->q, &q1);

	bn_mul(&phi, &p1, &q1);

	bignum_t e;
	bn_init(&e);
	bn_set_word(&e, 65537);

	bn_gcd(&gcd, &e, &phi);
	if (!bn_is_one(&gcd)) {
		fprintf(stderr, "rsa_keygen: bad e retry\n");
		return -1;
	}

	bn_copy(&key->e, &e);
	bn_mod_inv(&key->d, &e, &phi);

	bn_mod(&key->dp, &key->d, &p1);
	bn_mod(&key->dq, &key->d, &q1);

	bn_mod_inv(&key->qinv, &key->q, &key->p);

	return 0;
}

void rsa_print_key(const rsa_key_t *key)
{
	printf("RSA Key (%d bits):\n", key->bits);
	printf("  n: ");
	bn_print_hex(&key->n);
	printf("\n");
	printf("  e: ");
	bn_print_hex(&key->e);
	printf("\n");
	printf("  d: ");
	bn_print_hex(&key->d);
	printf("\n");
	printf("  p: ");
	bn_print_hex(&key->p);
	printf("\n");
	printf("  q: ");
	bn_print_hex(&key->q);
	printf("\n");
	printf("  dp: ");
	bn_print_hex(&key->dp);
	printf("\n");
	printf("  dq: ");
	bn_print_hex(&key->dq);
	printf("\n");
	printf("  qinv: ");
	bn_print_hex(&key->qinv);
	printf("\n");
}

void rsa_encrypt_block(bignum_t *c, const bignum_t *m, const rsa_key_t *key)
{
	if (bn_cmp(m, &key->n) >= 0) {
		fprintf(stderr, "rsa_encrypt_block: message too long\n");
		return;
	}

	bn_mod_exp(c, m, &key->e, &key->n);
}

void rsa_decrypt_block(bignum_t *m, const bignum_t *c, const rsa_key_t *key)
{
	/*
	 * CRT decryption:
	 *   m1 = c^dp mod p
	 *   m2 = c^dq mod q
	 *   h  = qinv * (m1 - m2) mod p
	 *   m  = m2 + h * q
	 */
	bignum_t m1, m2, h, tmp;

	bn_init(&m1);
	bn_init(&m2);
	bn_init(&h);
	bn_init(&tmp);

	bn_mod_exp(&m1, c, &key->dp, &key->p);
	bn_mod_exp(&m2, c, &key->dq, &key->q);

	/* (m1 - m2) mod p — handles m2 > p correctly */
	bn_mod_sub(&tmp, &m1, &m2, &key->p);
	bn_mod_mul(&h, &key->qinv, &tmp, &key->p);

	bn_mul(&tmp, &h, &key->q);
	bn_add(m, &m2, &tmp);
}

uint8_t *rsa_encrypt_image(const uint8_t *pixels, size_t pix_len,
			   const rsa_key_t *key, size_t *out_len)
{
	int key_bytes = RSA_KEY_BYTES(key);
	int block_in = key_bytes - 1;
	int block_out = key_bytes;

	size_t num_blocks = (pix_len + block_in - 1) / block_in;
	*out_len = 4 + num_blocks * block_out;

	uint8_t *out = (uint8_t *)malloc(*out_len);
	if (!out)
		return NULL;

	/* Store original plaintext length */
	out[0] = (uint8_t)(pix_len >> 24);
	out[1] = (uint8_t)(pix_len >> 16);
	out[2] = (uint8_t)(pix_len >> 8);
	out[3] = (uint8_t)(pix_len);

	for (size_t i = 0; i < num_blocks; i++) {
		size_t offset = i * block_in;
		size_t chunk = pix_len - offset;
		if (chunk > (size_t)block_in)
			chunk = block_in;
		bignum_t m, c;
		bn_init(&m);
		bn_init(&c);

		bn_from_bytes(&m, pixels + offset, chunk);
		rsa_encrypt_block(&c, &m, key);
		bn_to_bytes(&c, out + 4 + (i * block_out), block_out);
	}

	return out;
}

uint8_t *rsa_decrypt_image(const uint8_t *cipher, size_t cip_len,
			   const rsa_key_t *key, size_t *out_len)
{
	int key_bytes = RSA_KEY_BYTES(key);
	int block_in = key_bytes;
	int block_out = key_bytes - 1;

	if (cip_len < 4)
		return NULL;

	/* Read original plaintext length */
	size_t orig_len = ((size_t)cipher[0] << 24) |
			  ((size_t)cipher[1] << 16) |
			  ((size_t)cipher[2] << 8) | (size_t)cipher[3];

	size_t num_blocks = (cip_len - 4) / block_in;

	uint8_t *out = (uint8_t *)malloc(orig_len);
	if (!out)
		return NULL;

	uint8_t *tmp = (uint8_t *)malloc(block_out);

	for (size_t i = 0; i < num_blocks; i++) {
		bignum_t c, m;
		bn_init(&c);
		bn_init(&m);

		bn_from_bytes(&c, cipher + 4 + (i * block_in), block_in);
		rsa_decrypt_block(&m, &c, key);
		bn_to_bytes(&m, tmp, block_out);

		/* How many bytes does this block contribute? */
		size_t remaining = orig_len - i * block_out;
		size_t chunk = (remaining < (size_t)block_out) ? remaining
							       : (size_t)block_out;

		/* Data is right-aligned in big-endian, take last 'chunk' bytes */
		memcpy(out + i * block_out, tmp + (block_out - chunk), chunk);
	}

	free(tmp);
	*out_len = orig_len;
	return out;
}

uint8_t *rsa_oaep_encrypt_image(const uint8_t *pixels, size_t pix_len,
				const rsa_key_t *key, size_t *out_len)
{
	int k = RSA_KEY_BYTES(key);
	int max_msg = OAEP_MAX_MSG_LEN(k);

	if (max_msg <= 0) {
		fprintf(stderr, "rsa_oaep_encrypt: key too small for OAEP\n");
		return NULL;
	}

	size_t num_blocks = (pix_len + max_msg - 1) / max_msg;
	/* 4-byte header for original size + num_blocks * k ciphertext */
	*out_len = 4 + num_blocks * k;

	uint8_t *out = (uint8_t *)malloc(*out_len);
	if (!out)
		return NULL;

	/* Store original plaintext length in first 4 bytes (big-endian) */
	out[0] = (uint8_t)(pix_len >> 24);
	out[1] = (uint8_t)(pix_len >> 16);
	out[2] = (uint8_t)(pix_len >> 8);
	out[3] = (uint8_t)(pix_len);

	uint8_t *em = (uint8_t *)malloc(k);

	for (size_t i = 0; i < num_blocks; i++) {
		size_t offset = i * max_msg;
		size_t chunk = pix_len - offset;
		if (chunk > (size_t)max_msg)
			chunk = max_msg;

		if (oaep_encode(pixels + offset, chunk, k, em) != 0) {
			free(out);
			free(em);
			return NULL;
		}

		bignum_t m, c;
		bn_init(&m);
		bn_init(&c);
		bn_from_bytes(&m, em, k);
		rsa_encrypt_block(&c, &m, key);
		bn_to_bytes(&c, out + 4 + (i * k), k);
	}

	free(em);
	return out;
}

uint8_t *rsa_oaep_decrypt_image(const uint8_t *cipher, size_t cip_len,
				const rsa_key_t *key, size_t *out_len)
{
	int k = RSA_KEY_BYTES(key);
	int max_msg = OAEP_MAX_MSG_LEN(k);

	if (cip_len < 4) {
		fprintf(stderr, "rsa_oaep_decrypt: ciphertext too short\n");
		return NULL;
	}

	/* Read original plaintext length from header */
	size_t orig_len = ((size_t)cipher[0] << 24) |
			  ((size_t)cipher[1] << 16) | ((size_t)cipher[2] << 8) |
			  (size_t)cipher[3];

	size_t num_blocks = (cip_len - 4) / k;

	/* Allocate worst case, will trim to orig_len */
	uint8_t *out = (uint8_t *)malloc(num_blocks * max_msg);
	if (!out)
		return NULL;

	uint8_t *em = (uint8_t *)malloc(k);
	uint8_t *msg_buf = (uint8_t *)malloc(max_msg);
	size_t total = 0;

	for (size_t i = 0; i < num_blocks; i++) {
		bignum_t c, m;
		bn_init(&c);
		bn_init(&m);

		bn_from_bytes(&c, cipher + 4 + (i * k), k);
		rsa_decrypt_block(&m, &c, key);
		bn_to_bytes(&m, em, k);

		size_t msg_len = 0;
		if (oaep_decode(em, k, msg_buf, &msg_len) != 0) {
			fprintf(stderr, "rsa_oaep_decrypt: block %zu failed\n",
				i);
			free(out);
			free(em);
			free(msg_buf);
			return NULL;
		}

		memcpy(out + total, msg_buf, msg_len);
		total += msg_len;
	}

	free(em);
	free(msg_buf);

	*out_len = orig_len;
	return out;
}

int rsa_key_from_hex(rsa_key_t *key, const char *p_hex, const char *q_hex,
		     const char *e_hex)
{
	bn_init(&key->p);
	bn_init(&key->q);
	bn_init(&key->n);
	bn_init(&key->e);
	bn_init(&key->d);
	bn_init(&key->dp);
	bn_init(&key->dq);
	bn_init(&key->qinv);

	bn_from_hex(&key->p, p_hex);
	bn_from_hex(&key->q, q_hex);
	bn_from_hex(&key->e, e_hex);

	/* n = p * q */
	bn_mul(&key->n, &key->p, &key->q);
	key->bits = bn_bit_len(&key->n);

	/* phi = (p-1)(q-1) */
	bignum_t p1, q1, phi, gcd;
	bn_init(&p1);
	bn_init(&q1);
	bn_init(&phi);
	bn_init(&gcd);

	bn_set_word(&p1, 1);
	bn_set_word(&q1, 1);
	bn_sub(&p1, &key->p, &p1);
	bn_sub(&q1, &key->q, &q1);
	bn_mul(&phi, &p1, &q1);

	/* Verify gcd(e, phi) == 1 */
	bn_gcd(&gcd, &key->e, &phi);
	if (!bn_is_one(&gcd)) {
		fprintf(stderr,
			"rsa_key_from_hex: e is not coprime with phi(n)\n");
		return -1;
	}

	/* d = e^-1 mod phi */
	bn_mod_inv(&key->d, &key->e, &phi);

	/* CRT: dp = d mod (p-1), dq = d mod (q-1), qinv = q^-1 mod p */
	bn_mod(&key->dp, &key->d, &p1);
	bn_mod(&key->dq, &key->d, &q1);
	bn_mod_inv(&key->qinv, &key->q, &key->p);

	return 0;
}
