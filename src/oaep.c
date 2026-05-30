/*
 * oaep.c — OAEP encode/decode (PKCS#1 v2.2).
 *
 * Encode: DB = lHash || PS || 0x01 || M, then double-mask with MGF1.
 * Decode: reverse the masking, verify lHash, extract message.
 * SHA-256 is used for both hashing and MGF1.
 */
#include "oaep.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

/*
 * MGF1 using SHA-256.
 * Expands `seed` (seed_len bytes) into `mask` (mask_len bytes)
 * by hashing seed ‖ counter for counter = 0, 1, 2, ...
 */
static void mgf1_sha256(const uint8_t *seed, size_t seed_len, uint8_t *mask,
			size_t mask_len)
{
	size_t pos = 0;
	uint32_t counter = 0;

	while (pos < mask_len) {
		uint8_t hash[OAEP_HASH_LEN];
		uint8_t counter_be[4] = {
		    (uint8_t)(counter >> 24),
		    (uint8_t)(counter >> 16),
		    (uint8_t)(counter >> 8),
		    (uint8_t)(counter),
		};

		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
		EVP_DigestUpdate(ctx, seed, seed_len);
		EVP_DigestUpdate(ctx, counter_be, 4);
		EVP_DigestFinal_ex(ctx, hash, NULL);
		EVP_MD_CTX_free(ctx);

		size_t chunk = mask_len - pos;
		if (chunk > OAEP_HASH_LEN)
			chunk = OAEP_HASH_LEN;
		memcpy(mask + pos, hash, chunk);
		pos += chunk;
		counter++;
	}
}

/* SHA-256 of empty string (label hash, we use no label) */
static void lhash(uint8_t *out)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestFinal_ex(ctx, out, NULL);
	EVP_MD_CTX_free(ctx);
}

int oaep_encode(const uint8_t *msg, size_t msg_len, size_t k, uint8_t *em)
{
	size_t max_msg = OAEP_MAX_MSG_LEN(k);
	if (msg_len > max_msg) {
		fprintf(stderr, "oaep_encode: message too long (%zu > %zu)\n",
			msg_len, max_msg);
		return -1;
	}

	size_t db_len = k - OAEP_HASH_LEN - 1;
	uint8_t *db = (uint8_t *)calloc(db_len, 1);
	uint8_t seed[OAEP_HASH_LEN];

	/* DB = lHash ‖ PS(zeros) ‖ 0x01 ‖ M */
	lhash(db);
	/* PS is already zeros from calloc */
	size_t ps_len = db_len - OAEP_HASH_LEN - 1 - msg_len;
	db[OAEP_HASH_LEN + ps_len] = 0x01;
	memcpy(db + OAEP_HASH_LEN + ps_len + 1, msg, msg_len);

	/* Generate random seed */
	RAND_bytes(seed, OAEP_HASH_LEN);

	/* maskedDB = DB ⊕ MGF1(seed) */
	uint8_t *db_mask = (uint8_t *)malloc(db_len);
	mgf1_sha256(seed, OAEP_HASH_LEN, db_mask, db_len);
	for (size_t i = 0; i < db_len; i++)
		db[i] ^= db_mask[i];

	/* maskedSeed = seed ⊕ MGF1(maskedDB) */
	uint8_t seed_mask[OAEP_HASH_LEN];
	mgf1_sha256(db, db_len, seed_mask, OAEP_HASH_LEN);
	for (size_t i = 0; i < OAEP_HASH_LEN; i++)
		seed[i] ^= seed_mask[i];

	/* EM = 0x00 ‖ maskedSeed ‖ maskedDB */
	em[0] = 0x00;
	memcpy(em + 1, seed, OAEP_HASH_LEN);
	memcpy(em + 1 + OAEP_HASH_LEN, db, db_len);

	free(db);
	free(db_mask);
	return 0;
}

int oaep_decode(const uint8_t *em, size_t k, uint8_t *msg, size_t *msg_len)
{
	if (em[0] != 0x00) {
		fprintf(stderr, "oaep_decode: invalid first byte\n");
		return -1;
	}

	size_t db_len = k - OAEP_HASH_LEN - 1;
	const uint8_t *masked_seed = em + 1;
	const uint8_t *masked_db = em + 1 + OAEP_HASH_LEN;

	/* Recover seed = maskedSeed ⊕ MGF1(maskedDB) */
	uint8_t seed[OAEP_HASH_LEN];
	uint8_t seed_mask[OAEP_HASH_LEN];
	mgf1_sha256(masked_db, db_len, seed_mask, OAEP_HASH_LEN);
	for (size_t i = 0; i < OAEP_HASH_LEN; i++)
		seed[i] = masked_seed[i] ^ seed_mask[i];

	/* Recover DB = maskedDB ⊕ MGF1(seed) */
	uint8_t *db = (uint8_t *)malloc(db_len);
	uint8_t *db_mask = (uint8_t *)malloc(db_len);
	mgf1_sha256(seed, OAEP_HASH_LEN, db_mask, db_len);
	for (size_t i = 0; i < db_len; i++)
		db[i] = masked_db[i] ^ db_mask[i];

	/* Verify lHash */
	uint8_t expected_lhash[OAEP_HASH_LEN];
	lhash(expected_lhash);
	if (memcmp(db, expected_lhash, OAEP_HASH_LEN) != 0) {
		fprintf(stderr, "oaep_decode: lHash mismatch\n");
		free(db);
		free(db_mask);
		return -1;
	}

	/* Find 0x01 separator after PS */
	size_t i = OAEP_HASH_LEN;
	while (i < db_len && db[i] == 0x00)
		i++;

	if (i >= db_len || db[i] != 0x01) {
		fprintf(stderr, "oaep_decode: no 0x01 separator found\n");
		free(db);
		free(db_mask);
		return -1;
	}
	i++; /* skip the 0x01 */

	/* Extract message */
	*msg_len = db_len - i;
	memcpy(msg, db + i, *msg_len);

	free(db);
	free(db_mask);
	return 0;
}
