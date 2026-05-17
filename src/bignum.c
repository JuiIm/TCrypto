#include "bignum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Lifecycle ─────────────────────────────────────────────── */
void bn_init(bignum_t *a)
{
	memset(a, 0, sizeof(bignum_t));
	a->len = 1;
}

void bn_copy(bignum_t *dst, const bignum_t *src)
{
	memcpy(dst, src, sizeof(bignum_t));
}

void bn_trim(bignum_t *a)
{
	while (a->len > 1 && a->limbs[a->len - 1] == 0) {
		a->len--;
	}
	if (a->len == 1 && a->limbs[0] == 0)
		a->sign = 0;
}

void bn_set_word(bignum_t *a, uint32_t w)
{
	bn_init(a);
	a->limbs[0] = w;
}

int bn_cmp_abs(const bignum_t *a, const bignum_t *b)
{
	if (a->len > b->len)
		return 1;
	if (a->len < b->len)
		return -1;

	for (int i = a->len - 1; i >= 0; i--) {
		if (a->limbs[i] > b->limbs[i])
			return 1;
		if (a->limbs[i] < b->limbs[i])
			return -1;
	}

	return 0;
}

int bn_cmp(const bignum_t *a, const bignum_t *b)
{
	if (a->sign != b->sign) {
		if (bn_is_zero(a) && bn_is_zero(b)) return 0;
		return a->sign ? -1 : 1;
	}

	if (a->sign == 0)
		return bn_cmp_abs(a, b);
	else
		return -bn_cmp_abs(a, b);
}

bool bn_is_zero(const bignum_t *a)
{
	return a->len == 1 && a->limbs[0] == 0;
}

bool bn_is_one(const bignum_t *a)
{
	return a->len == 1 && a->limbs[0] == 1 && a->sign == 0;
}

bool bn_is_even(const bignum_t *a)
{
	return (a->limbs[0] & 1) == 0;
}

int bn_get_bit(const bignum_t *a, int bit)
{
	int limb_idx = bit / 32;
	int limb_off = bit % 32;

	if (limb_idx >= a->len)
		return 0;

	return (a->limbs[limb_idx] >> limb_off) & 1;
}

void bn_set_bit(bignum_t *a, int bit)
{
	int limb_idx = bit / 32;
	int limb_off = bit % 32;

	if (limb_idx >= BN_MAX_LIMBS) {
		return; // add err handling later
	}

	a->limbs[limb_idx] |= (1U << limb_off);

	if (limb_idx >= a->len)
		a->len = limb_idx + 1;
}

int bn_bit_len(const bignum_t *a)
{
	if (a->len == 0)
		return 0;

	uint32_t top = a->limbs[a->len - 1];

	int bits = 0;
	while (top) {
		top >>= 1;
		bits++;
	}

	return (a->len - 1) * 32 + bits;
}

void bn_shr(bignum_t *a, int bits)
{
	if (a->len == 0 || bits == 0)
		return;

	int limb_shift = bits / 32;
	int bit_shift = bits % 32;

	if (limb_shift >= a->len) {
		bn_init(a);
		return;
	}

	uint32_t out[BN_MAX_LIMBS] = {0};
	int new_len = a->len - limb_shift;

	for (int i = 0; i < new_len; i++) {
		uint32_t low = a->limbs[i + limb_shift] >> bit_shift;

		uint32_t high = 0;
		if (bit_shift > 0 && (i + limb_shift + 1) < a->len) {
			high = a->limbs[i + limb_shift + 1] << (32 - bit_shift);
		}
		out[i] = low | high;
	}
	memcpy(a->limbs, out, sizeof(uint32_t) * new_len);
	a->len = new_len;
	bn_trim(a);
}

void bn_shl(bignum_t *a, int bits)
{
	if (bn_is_zero(a) || bits == 0)
		return;

	int limb_shift = bits / 32;
	int bit_shift = bits % 32;

	int new_len = a->len + limb_shift + (bit_shift > 0 ? 1 : 0);
	if (new_len > BN_MAX_LIMBS) {
		fprintf(stderr, "bn_shl: overflow\n");
		return;
	}

	uint32_t out[BN_MAX_LIMBS] = {0};

	for (int i = a->len - 1; i >= 0; i--) {
		uint64_t v = (uint64_t)a->limbs[i];
		int target = i + limb_shift;

		out[target] |= (uint32_t)(v << bit_shift);

		if (bit_shift != 0 && target + 1 < BN_MAX_LIMBS) {
			out[target + 1] |= (uint32_t)(v >> (32 - bit_shift));
		}
	}

	memcpy(a->limbs, out, sizeof(out));
	a->len = new_len;
	bn_trim(a);
}

void bn_add_abs(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	bignum_t tmp;
	bn_init(&tmp);

	uint64_t carry = 0;
	int max_len = (a->len > b->len) ? a->len : b->len;

	for (int i = 0; i < max_len || carry; i++) {
		uint64_t sum = carry;
		if (i < a->len) sum += (uint64_t)a->limbs[i];
		if (i < b->len) sum += (uint64_t)b->limbs[i];
		tmp.limbs[i] = (uint32_t)(sum & 0xFFFFFFFF);
		carry = sum >> 32;
		tmp.len = i + 1;
	}

	bn_trim(&tmp);
	bn_copy(r, &tmp);
}