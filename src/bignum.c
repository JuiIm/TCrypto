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
		if (bn_is_zero(a) && bn_is_zero(b))
			return 0;
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

void bn_from_hex(bignum_t *a, const char *hex)
{
	bn_init(a);
	if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
		hex += 2;

	size_t slen = strlen(hex);
	if (slen == 0)
		return;

	size_t byte_len = (slen + 1) / 2;
	uint8_t bytes[512] = {0};

	for (size_t i = 0; i < slen; i++) {
		char c = hex[slen - 1 - i];
		uint8_t v;
		if (c >= '0' && c <= '9')
			v = (uint8_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = (uint8_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			v = (uint8_t)(c - 'A' + 10);
		else
			return;

		size_t bi = byte_len - 1 - i / 2;
		if (i % 2 == 0)
			bytes[bi] = v;
		else
			bytes[bi] |= (uint8_t)(v << 4);
	}

	while (byte_len > 0 && bytes[0] == 0) {
		bytes[0] = bytes[1];
		memmove(bytes, bytes + 1, byte_len - 1);
		byte_len--;
	}

	int nlimbs = (int)((byte_len + 3) / 4);
	a->len = nlimbs > 0 ? nlimbs : 1;

	for (size_t i = 0; i < byte_len; i++) {
		int limb_idx = (int)(i / 4);
		int shift = (int)((i % 4) * 8);
		a->limbs[limb_idx] |= (uint32_t)bytes[byte_len - 1 - i]
				      << shift;
	}
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
		if (i < a->len)
			sum += (uint64_t)a->limbs[i];
		if (i < b->len)
			sum += (uint64_t)b->limbs[i];
		tmp.limbs[i] = (uint32_t)(sum & 0xFFFFFFFF);
		carry = sum >> 32;
		tmp.len = i + 1;
	}

	bn_trim(&tmp);
	bn_copy(r, &tmp);
}

/* This assumes a >= b since we are performing unsigned subtraction */
void bn_sub_abs(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	bignum_t tmp;
	bn_init(&tmp);

	uint64_t borrow = 0;

	if (a->len < b->len) {
		fprintf(stderr, "bn_sub_abs: a < b\n");
		return;
	}

	for (int i = 0; i < a->len; i++) {
		int64_t diff = (int64_t)a->limbs[i] - borrow;
		if (i < b->len)
			diff -= (int64_t)b->limbs[i];
		if (diff < 0) {
			diff += BN_BASE;
			borrow = 1;
		} else {
			borrow = 0;
		}
		tmp.limbs[i] = (uint32_t)(diff & 0xFFFFFFFF);
		tmp.len = i + 1;
	}

	bn_trim(&tmp);
	bn_copy(r, &tmp);
}

void bn_add(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	if (a->sign == b->sign) {
		bn_add_abs(r, a, b);
		r->sign = a->sign;
	} else {
		int cmp = bn_cmp_abs(a, b);
		if (cmp == 0) {
			bn_init(r);
		} else if (cmp > 0) {
			bn_sub_abs(r, a, b);
			r->sign = a->sign;
		} else {
			bn_sub_abs(r, b, a);
			r->sign = b->sign;
		}
	}
}

void bn_sub(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	if (a->sign != b->sign) {
		bn_add_abs(r, a, b);
		r->sign = a->sign;
	} else {
		int cmp = bn_cmp_abs(a, b);
		if (cmp == 0) {
			bn_init(r);
		} else if (cmp > 0) {
			bn_sub_abs(r, a, b);
			r->sign = a->sign;
		} else {
			bn_sub_abs(r, b, a);
			r->sign = !b->sign;
		}
	}
}

void bn_mul(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	bignum_t tmp;
	bn_init(&tmp);

	if (bn_is_zero(a) || bn_is_zero(b)) {
		bn_copy(r, &tmp);
		return;
	}

	int rlen = a->len + b->len;
	if (rlen > BN_MAX_LIMBS) {
		fprintf(stderr, "bn_mul: overflow (%d limbs)\n", rlen);
		return;
	}
	tmp.len = rlen;

	for (int i = 0; i < a->len; i++) {
		uint64_t carry = 0;
		for (int j = 0; j < b->len; j++) {
			uint64_t prod =
			    (uint64_t)a->limbs[i] * (uint64_t)b->limbs[j] +
			    (uint64_t)tmp.limbs[i + j] + carry;
			tmp.limbs[i + j] = (uint32_t)(prod & 0xFFFFFFFF);
			carry = prod >> 32;
		}
		if (carry)
			tmp.limbs[i + b->len] += (uint32_t)carry;
	}

	tmp.sign = a->sign ^ b->sign;
	bn_trim(&tmp);
	bn_copy(r, &tmp);
}
