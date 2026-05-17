#include "bignum.h"
#include <stdio.h>

static int pass = 0, fail = 0;

static void check(const char *name, const bignum_t *got, const char *hex)
{
	bignum_t exp;
	bn_from_hex(&exp, hex);
	if (bn_cmp_abs(got, &exp) == 0) {
		pass++;
	} else {
		printf("  FAIL: %s\n", name);
		fail++;
	}
}

static void chk(const char *name, int got, int expected)
{
	if (got == expected) {
		pass++;
	} else {
		printf("  FAIL: %s (got %d)\n", name, got);
		fail++;
	}
}

int main(void)
{
	bignum_t a, b, r;

	/* Arithmetic */
	bn_set_word(&a, 0xFFFFFFFF);
	bn_set_word(&b, 1);
	bn_add(&r, &a, &b);
	check("add carry", &r, "100000000");

	bn_from_hex(&a, "100000000");
	bn_set_word(&b, 1);
	bn_sub(&r, &a, &b);
	check("sub borrow", &r, "FFFFFFFF");

	bn_set_word(&a, 0xFFFFFFFF);
	bn_set_word(&b, 0xFFFFFFFF);
	bn_mul(&r, &a, &b);
	check("mul carry", &r, "FFFFFFFE00000001");

	/* Division */
	bn_set_word(&a, 1000000);
	bn_set_word(&b, 127);
	bignum_t q;
	bn_divmod(&q, &r, &a, &b);
	bignum_t v;
	bn_mul(&v, &q, &b);
	bn_add(&v, &v, &r);
	check("q*b+r==a", &v, "F4240");

	/* Mod exp (RSA) */
	bn_set_word(&a, 42);
	bn_set_word(&b, 17);
	bignum_t n;
	bn_set_word(&n, 3233);
	bn_mod_exp(&r, &a, &b, &n);
	check("RSA enc", &r, "9FD");
	bn_set_word(&b, 2753);
	bn_mod_exp(&r, &r, &b, &n);
	check("RSA dec", &r, "2A");

	/* Mod inverse */
	bn_set_word(&a, 17);
	bn_set_word(&n, 3120);
	bn_mod_inv(&r, &a, &n);
	check("mod_inv", &r, "AC1");

	/* Primality */
	bn_set_word(&a, 65537);
	chk("65537 prime", bn_is_prime_mr(&a, 20), 1);
	bn_set_word(&a, 65536);
	chk("65536 composite", bn_is_prime_mr(&a, 20), 0);

	/* Prime generation */
	bn_gen_prime(&a, 64);
	chk("gen 64-bit prime", bn_is_prime_mr(&a, 20), 1);
	chk("gen 64-bit len", bn_bit_len(&a), 64);

	printf("%d passed, %d failed\n", pass, fail);
	return fail > 0 ? 1 : 0;
}