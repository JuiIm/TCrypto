#include "bignum.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	printf("=== Generating a 512-bit RSA key ===\n");
	rsa_key_t gen;
	rsa_keygen(&gen, 512);

	char *p_hex = bn_to_hex_str(&gen.p);
	char *q_hex = bn_to_hex_str(&gen.q);

	printf("  p = \"%s\"\n", p_hex);
	printf("  q = \"%s\"\n", q_hex);
	printf("  e = \"10001\"\n\n");

	printf("=== Rebuilding key from hex ===\n");
	rsa_key_t key;
	if (rsa_key_from_hex(&key, p_hex, q_hex, "10001") != 0) {
		fprintf(stderr, "Failed to build key\n");
		return 1;
	}
	rsa_print_key(&key);

	printf("\nKeys match: n=%s, d=%s\n",
	       bn_cmp(&gen.n, &key.n) == 0 ? "YES" : "NO",
	       bn_cmp(&gen.d, &key.d) == 0 ? "YES" : "NO");

	const char *message = "Hello from custom key!";
	size_t msg_len = strlen(message);
	int k = RSA_KEY_BYTES(&key);

	printf("\nPlaintext : \"%s\" (%zu bytes)\n", message, msg_len);

	bignum_t m, c, dec;
	bn_init(&m);
	bn_init(&c);
	bn_init(&dec);

	bn_from_bytes(&m, (const uint8_t *)message, msg_len);

	printf("m (hex)   : ");
	bn_print_hex(&m);
	printf("\n");

	rsa_encrypt_block(&c, &m, &key);
	printf("c (hex)   : ");
	bn_print_hex(&c);
	printf("\n");

	rsa_decrypt_block(&dec, &c, &key);
	printf("dec (hex) : ");
	bn_print_hex(&dec);
	printf("\n");

	uint8_t recovered[256] = {0};
	bn_to_bytes(&dec, recovered, k - 1);

	size_t start = (k - 1) - msg_len;
	printf("Recovered : \"%.*s\"\n", (int)msg_len, recovered + start);

	int ok = (memcmp(recovered + start, message, msg_len) == 0);
	printf("Match     : %s\n", ok ? "OK" : "MISMATCH");

	free(p_hex);
	free(q_hex);
	return 0;
}
