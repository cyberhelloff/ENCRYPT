#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define SALT_SIZE 16
#define HMAC_SIZE 32
#define PBKDF2_ITERATIONS 100000

typedef struct {
    unsigned char salt[SALT_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char hmac[HMAC_SIZE];
} crypto_header_t;

int derive_key(const char *password, const unsigned char *salt, unsigned char *key);
int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);
void secure_wipe(void *ptr, size_t len);

#endif
