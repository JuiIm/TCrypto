#ifndef AES_CBC_H
#define AES_CBC_H

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE  32
#define AES_IV_SIZE   16
#define AES_BLOCK_SIZE 16

int aes_cbc_encrypt(const uint8_t *pt, size_t pt_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ct, size_t *ct_len);

int aes_cbc_decrypt(const uint8_t *ct, size_t ct_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *pt, size_t *pt_len);

void aes_generate_key_iv(uint8_t key[AES_KEY_SIZE], uint8_t iv[AES_IV_SIZE]);

#endif /* AES_CBC_H */
