#include "bignum.h"
#include <stdio.h>

/* Helper print bignum for debugging */
void print_bignum(const bignum_t *a)
{
	printf("0x");
	for (int i = a->len - 1; i >= 0; i--) {
		printf("%08x", a->limbs[i]);
	}
	printf("\n");
}

int main()
{
	bignum_t a = {.limbs = {0x00000001}, .len = 1, .sign = 0};

	bignum_t b = {.limbs = {0x00000010}, .len = 1, .sign = 0};

	print_bignum(&a);
	print_bignum(&b);

	bignum_t c;
	bn_init(&c);
	bn_add_abs(&c, &a, &b);
	print_bignum(&c);
	return 0;
}