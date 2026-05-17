#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BN_MAX_LIMBS 128

#define BN_BASE ((uint64_t)1 << 32)

typedef struct {
	uint32_t limbs[BN_MAX_LIMBS];
	int len;
	int sign;
} bignum_t;

void bn_init(bignum_t *a);
void bn_copy(bignum_t *dst, const bignum_t *src);
void bn_set_word(bignum_t *a, uint32_t w);

void bn_from_bytes(bignum_t *a, const uint8_t *buf, size_t len);
void bn_to_bytes(const bignum_t *a, uint8_t *buf, size_t len);
void bn_from_hex(bignum_t *a, const char *hex);
void bn_print_hex(const bignum_t *a);

int bn_cmp(const bignum_t *a, const bignum_t *b);
int bn_cmp_abs(const bignum_t *a, const bignum_t *b);
bool bn_is_zero(const bignum_t *a);
bool bn_is_one(const bignum_t *a);
bool bn_is_even(const bignum_t *a);

int bn_bit_len(const bignum_t *a);
int bn_get_bit(const bignum_t *a, int bit);
void bn_set_bit(bignum_t *a, int bit);
void bn_shr(bignum_t *a, int bits);
void bn_shl(bignum_t *a, int bits);

void bn_add(bignum_t *r, const bignum_t *a, const bignum_t *b);
void bn_sub(bignum_t *r, const bignum_t *a, const bignum_t *b);
void bn_mul(bignum_t *r, const bignum_t *a, const bignum_t *b);
void bn_divmod(bignum_t *q, bignum_t *rem, const bignum_t *a,
	       const bignum_t *b);

void bn_mod(bignum_t *r, const bignum_t *a, const bignum_t *n);
void bn_mod_add(bignum_t *r, const bignum_t *a, const bignum_t *b,
		const bignum_t *n);
void bn_mod_sub(bignum_t *r, const bignum_t *a, const bignum_t *b,
		const bignum_t *n);
void bn_mod_mul(bignum_t *r, const bignum_t *a, const bignum_t *b,
		const bignum_t *n);
void bn_mod_exp(bignum_t *r, const bignum_t *base, const bignum_t *exp,
		const bignum_t *mod);
void bn_mod_inv(bignum_t *r, const bignum_t *a, const bignum_t *n);
void bn_gcd(bignum_t *r, const bignum_t *a, const bignum_t *b);

void bn_rand(bignum_t *a, int bits);
bool bn_is_prime_mr(const bignum_t *n, int rounds);
void bn_gen_prime(bignum_t *p, int bits);

void bn_trim(bignum_t *a);
void bn_add_abs(bignum_t *r, const bignum_t *a, const bignum_t *b);
void bn_sub_abs(bignum_t *r, const bignum_t *a, const bignum_t *b);

#endif /* BIGNUM_H */
