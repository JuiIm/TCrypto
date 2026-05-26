#include "bignum.h"
#include <openssl/rand.h>
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
		for (int k = i + b->len; carry && k < rlen; k++) {
			uint64_t s = (uint64_t)tmp.limbs[k] + carry;
			tmp.limbs[k] = (uint32_t)(s & 0xFFFFFFFF);
			carry = s >> 32;
		}
	}

	tmp.sign = a->sign ^ b->sign;
	bn_trim(&tmp);
	bn_copy(r, &tmp);
}

/* We use the restoring division algorithm we covered in the first semester*/
void bn_divmod(bignum_t *q, bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	if (bn_is_zero(b)) {
		fprintf(stderr, "bn_divmod: division by zero\n");
		return;
	}

	if (bn_cmp_abs(a, b) < 0) {
		if (q)
			bn_init(q);
		if (r) {
			bn_copy(r, a);
			r->sign = 0;
		}
		return;
	}

	if (bn_cmp_abs(a, b) == 0) {
		if (q)
			bn_set_word(q, 1);
		if (r)
			bn_init(r);
		return;
	}

	if (b->len == 1) {
		uint32_t d = b->limbs[0];
		bignum_t Q;
		bn_init(&Q);
		Q.len = a->len;
		uint64_t carry = 0;

		for (int i = a->len - 1; i >= 0; i--) {
			uint64_t cur = (carry << 32) | a->limbs[i];
			Q.limbs[i] = (uint32_t)(cur / d);
			carry = cur % d;
		}
		bn_trim(&Q);

		if (q)
			bn_copy(q, &Q);
		if (r)
			bn_set_word(r, (uint32_t)carry);
		return;
	}

	bignum_t R, Q;
	bn_init(&R);
	bn_init(&Q);
	int n = bn_bit_len(a);

	for (int i = n - 1; i >= 0; i--) {
		bn_shl(&R, 1);

		if (bn_get_bit(a, i))
			R.limbs[0] |= 1;

		if (bn_cmp_abs(&R, b) >= 0) {
			bn_sub_abs(&R, &R, b);
			bn_set_bit(&Q, i);
		}
	}

	if (q)
		bn_copy(q, &Q);
	if (r)
		bn_copy(r, &R);
}

void bn_mod(bignum_t *r, const bignum_t *a, const bignum_t *n)
{
	bignum_t abs_a, rem;
	bn_init(&rem);
	bn_copy(&abs_a, a);
	abs_a.sign = 0;
	bn_divmod(NULL, &rem, &abs_a, n);
	if (a->sign && !bn_is_zero(&rem))
		bn_sub(&rem, n, &rem);
	bn_copy(r, &rem);
}

void bn_mod_add(bignum_t *r, const bignum_t *a, const bignum_t *b,
		const bignum_t *n)
{
	bignum_t sum;
	bn_init(&sum);
	bn_add(&sum, a, b);
	bn_mod(r, &sum, n);
}

void bn_mod_sub(bignum_t *r, const bignum_t *a, const bignum_t *b,
		const bignum_t *n)
{
	bignum_t diff;
	bn_init(&diff);
	bn_sub(&diff, a, b);
	bn_mod(r, &diff, n);
}

void bn_mod_mul(bignum_t *r, const bignum_t *a, const bignum_t *b,
		const bignum_t *n)
{
	bignum_t prod;
	bn_init(&prod);
	bn_mul(&prod, a, b);
	bn_mod(r, &prod, n);
}

/* Left to right fast exponentiation we covered in class*/
void bn_mod_exp(bignum_t *r, const bignum_t *base, const bignum_t *exp,
		const bignum_t *mod)
{
	if (bn_is_one(mod)) {
		bn_init(r);
		return;
	}

	bignum_t result, b;
	bn_init(&result);
	bn_init(&b);
	bn_set_word(&result, 1);
	bn_mod(&b, base, mod);

	int exp_bits = bn_bit_len(exp);

	for (int i = exp_bits - 1; i >= 0; i--) {
		bn_mod_mul(&result, &result, &result, mod);
		if (bn_get_bit(exp, i)) {
			bn_mod_mul(&result, &result, &b, mod);
		}
	}

	bn_copy(r, &result);
}

void bn_gcd(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
	bignum_t x, y, tmp;
	bn_init(&x);
	bn_init(&y);
	bn_init(&tmp);
	bn_copy(&x, a);
	x.sign = 0;
	bn_copy(&y, b);
	y.sign = 0;

	while (!bn_is_zero(&y)) {
		bn_mod(&tmp, &x, &y);
		bn_copy(&x, &y);
		bn_copy(&y, &tmp);
	}
	bn_copy(r, &x);
}

void bn_mod_inv(bignum_t *r, const bignum_t *a, const bignum_t *n)
{
	bignum_t old_r, rr, old_s, s, quotient, tmp, tmp2;

	bn_init(&old_r);
	bn_init(&rr);
	bn_init(&s);
	bn_init(&quotient);
	bn_init(&tmp);
	bn_init(&tmp2);

	bn_copy(&old_r, n);
	bn_mod(&rr, a, n);
	bn_init(&old_s);
	bn_set_word(&s, 1);

	while (!bn_is_zero(&rr)) {
		bn_divmod(&quotient, NULL, &old_r, &rr);

		bn_copy(&tmp, &rr);
		bn_mul(&tmp2, &quotient, &rr);
		bn_sub(&rr, &old_r, &tmp2);
		bn_copy(&old_r, &tmp);

		bn_copy(&tmp, &s);
		bn_mul(&tmp2, &quotient, &s);
		bn_sub(&s, &old_s, &tmp2);
		bn_copy(&old_s, &tmp);
	}

	if (old_s.sign)
		bn_add(r, &old_s, n);
	else
		bn_copy(r, &old_s);
}

void bn_from_bytes(bignum_t *a, const uint8_t *buf, size_t len)
{
	bn_init(a);
	if (len == 0)
		return;

	while (len > 0 && *buf == 0) {
		buf++;
		len--;
	}
	if (len == 0)
		return;

	int nlimbs = (int)((len + 3) / 4);
	if (nlimbs > BN_MAX_LIMBS) {
		fprintf(stderr, "bn_from_bytes: too large\n");
		return;
	}
	a->len = nlimbs;

	for (int i = 0; i < len; i++) {
		int limb_idx = (int)(i / 4);
		int shift = (int)((i % 4) * 8);
		a->limbs[limb_idx] |= (uint32_t)buf[len - 1 - i] << shift;
	}
	bn_trim(a);
}

void bn_to_bytes(const bignum_t *a, uint8_t *buf, size_t len)
{
	memset(buf, 0, len);
	for (int i = 0; i < a->len; i++) {
		uint32_t limb = a->limbs[i];
		for (int j = 0; j < 4; j++) {
			size_t byte_idx = (size_t)(i * 4 + j);
			if (byte_idx >= len)
				break;
			buf[len - 1 - byte_idx] = (uint8_t)(limb >> (j * 8));
		}
	}
}

void bn_print_hex(const bignum_t *a)
{
	if (a->sign)
		printf("-");
	int start = a->len - 1;
	printf("%x", a->limbs[start]);
	for (int i = start - 1; i >= 0; i--)
		printf("%08x", a->limbs[i]);
}

void bn_rand(bignum_t *a, int bits)
{
	if (bits <= 0) {
		bn_init(a);
		return;
	}

	int byte_len = (bits + 7) / 8;
	uint8_t *buf = (uint8_t *)calloc((size_t)byte_len, 1);
	if (!buf) {
		fprintf(stderr, "bn_rand: alloc failed\n");
		exit(1);
	}

	RAND_bytes(buf, byte_len);

	int excess = byte_len * 8 - bits;
	if (excess > 0)
		buf[0] &= (uint8_t)(0xFF >> excess);

	int top_bit = (bits - 1) % 8;
	buf[0] |= (uint8_t)(1 << top_bit);

	bn_from_bytes(a, buf, (size_t)byte_len);
	a->sign = 0;
	free(buf);
}

static const uint16_t small_primes[] = {
    3,	 5,   7,   11,	13,  17,  19,  23,  29,	 31,  37,  41,	43,  47,
    53,	 59,  61,  67,	71,  73,  79,  83,  89,	 97,  101, 103, 107, 109,
    113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
    271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
    359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
    443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
    541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
    619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
    719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
    911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997};
#define NUM_SMALL_PRIMES (sizeof(small_primes) / sizeof(small_primes[0]))

bool bn_is_prime_mr(const bignum_t *n, int rounds)
{
	if (bn_is_zero(n) || bn_is_one(n))
		return false;

	bignum_t two, three;
	bn_init(&two);
	bn_init(&three);
	bn_set_word(&two, 2);
	bn_set_word(&three, 3);

	if (bn_cmp(n, &two) == 0 || bn_cmp(n, &three) == 0)
		return true;
	if (bn_is_even(n))
		return false;

	/* Trial division by small primes */
	for (size_t i = 0; i < NUM_SMALL_PRIMES; i++) {
		bignum_t sp, rem;
		bn_set_word(&sp, small_primes[i]);
		if (bn_cmp(n, &sp) == 0)
			return true;
		bn_mod(&rem, n, &sp);
		if (bn_is_zero(&rem))
			return false;
	}

	/* Write n-1 = 2^s * d where d is odd */
	bignum_t n_minus_1, d, one;
	bn_init(&n_minus_1);
	bn_init(&d);
	bn_init(&one);
	bn_set_word(&one, 1);
	bn_sub(&n_minus_1, n, &one);
	bn_copy(&d, &n_minus_1);

	int s = 0;
	while (bn_is_even(&d)) {
		bn_shr(&d, 1);
		s++;
	}

	/* Miller-Rabin rounds */
	for (int i = 0; i < rounds; i++) {
		bignum_t a;
		int n_bits = bn_bit_len(n);
		do {
			bn_rand(&a, n_bits);
			bn_mod(&a, &a, n);
		} while (bn_cmp(&a, &two) < 0 || bn_cmp(&a, &n_minus_1) >= 0);

		bignum_t x;
		bn_init(&x);
		bn_mod_exp(&x, &a, &d, n);

		if (bn_is_one(&x) || bn_cmp(&x, &n_minus_1) == 0)
			continue;

		bool found = false;
		for (int j = 0; j < s - 1; j++) {
			bn_mod_mul(&x, &x, &x, n);
			if (bn_cmp(&x, &n_minus_1) == 0) {
				found = true;
				break;
			}
		}
		if (!found)
			return false;
	}

	return true;
}

void bn_gen_prime(bignum_t *p, int bits)
{
	do {
		bn_rand(p, bits);
		p->limbs[0] |= 1; /* ensure odd */
	} while (!bn_is_prime_mr(p, 40));
}
