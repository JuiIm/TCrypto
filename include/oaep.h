/*
 * oaep.h — PKCS#1 v2.2 OAEP padding (SHA-256 + MGF1).
 * Provides semantic security: identical plaintexts produce
 * different ciphertexts thanks to a random seed.
 */
#ifndef OAEP_H
#define OAEP_H

#include <stddef.h>
#include <stdint.h>

/* SHA-256 digest length in bytes */
#define OAEP_HASH_LEN 32

/* Maximum message length for OAEP with key size k:
 * max_msg = k - 2*hLen - 2 */
#define OAEP_MAX_MSG_LEN(k) ((k) - 2 * OAEP_HASH_LEN - 2)

/*
 * OAEP encode a message.
 *
 * msg      : plaintext message
 * msg_len  : length of message (must be <= OAEP_MAX_MSG_LEN(k))
 * k        : RSA key size in bytes (256 for 2048-bit RSA)
 * em       : output encoded message buffer (must be k bytes)
 *
 * Returns 0 on success, -1 on error.
 */
int oaep_encode(const uint8_t *msg, size_t msg_len, size_t k, uint8_t *em);

/*
 * OAEP decode an encoded message.
 *
 * em       : encoded message (k bytes)
 * k        : RSA key size in bytes
 * msg      : output plaintext buffer
 * msg_len  : output plaintext length
 *
 * Returns 0 on success, -1 on decoding error.
 */
int oaep_decode(const uint8_t *em, size_t k, uint8_t *msg, size_t *msg_len);

#endif /* OAEP_H */