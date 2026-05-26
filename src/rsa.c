#include "rsa.h"
#include "bignum.h"
#include <stdio.h>
#include <stdlib.h>

int rsa_keygen(rsa_key_t *key, int bits)
{
	if (bits < 512) {
		fprintf(stderr,
			"rsa_keygen: key size must be at least 512 bits\n");
		return -1;
	}

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
	*out_len = num_blocks * block_out;

	uint8_t *out = (uint8_t *)malloc(*out_len);
	if (!out)
		return NULL;
	for (int i = 0; i < num_blocks; i++) {
		size_t offset = i * block_in;
		size_t chunk = pix_len - offset;
		if (chunk > (size_t)block_in)
			chunk = block_in;
		bignum_t m, c;
		bn_init(&m);
		bn_init(&c);

		bn_from_bytes(&m, pixels + offset, chunk);
		rsa_encrypt_block(&c, &m, key);
		bn_to_bytes(&c, out + (i * block_out), block_out);
	}

	return out;
}

uint8_t *rsa_decrypt_image(const uint8_t *cipher, size_t cip_len,
			   const rsa_key_t *key, size_t *out_len)
{
	int key_bytes = RSA_KEY_BYTES(key);
	int block_in = key_bytes;
	int block_out = key_bytes - 1;

	size_t num_blocks = cip_len / block_in;
	*out_len = num_blocks * block_out;

	uint8_t *out = (uint8_t *)malloc(*out_len);

	if (!out)
		return NULL;

	for (int i = 0; i < num_blocks; i++) {
		bignum_t c, m;
		bn_init(&c);
		bn_init(&m);

		bn_from_bytes(&c, cipher + (i * block_in), block_in);
		rsa_decrypt_block(&m, &c, key);
		bn_to_bytes(&m, out + (i * block_out), block_out);
	}

	return out;
}