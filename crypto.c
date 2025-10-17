#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_SIZE, key);
}

void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) return -1;

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    crypto_header_t header;
    if (!RAND_bytes(header.salt, SALT_SIZE) || !RAND_bytes(header.iv, AES_BLOCK_SIZE)) {
        fclose(in);
        fclose(out);
        return -1;
    }

    unsigned char key[AES_KEY_SIZE];
    if (!derive_key(password, header.salt, key)) {
        fclose(in);
        fclose(out);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, header.iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    // Write header
    if (fwrite(&header, sizeof(crypto_header_t), 1, out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    unsigned char inbuf[4096], outbuf[4096 + AES_BLOCK_SIZE];
    int inlen, outlen;
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    if (HMAC_Init_ex(hmac_ctx, key, AES_KEY_SIZE, EVP_sha256(), NULL) != 1) {
        HMAC_CTX_free(hmac_ctx);
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) break;
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) break;
        HMAC_Update(hmac_ctx, outbuf, outlen);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) == 1) {
        fwrite(outbuf, 1, outlen, out);
        HMAC_Update(hmac_ctx, outbuf, outlen);
    }

    HMAC_Final(hmac_ctx, header.hmac, NULL);
    fseek(out, 0, SEEK_SET);
    fwrite(&header, sizeof(crypto_header_t), 1, out);

    HMAC_CTX_free(hmac_ctx);
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    secure_wipe(key, AES_KEY_SIZE);

    return 0;
}

int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    if (!in) return -1;

    crypto_header_t header;
    if (fread(&header, sizeof(crypto_header_t), 1, in) != 1) {
        fclose(in);
        return -1;
    }

    unsigned char key[AES_KEY_SIZE];
    if (!derive_key(password, header.salt, key)) {
        fclose(in);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(in);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, header.iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    unsigned char inbuf[4096], outbuf[4096 + AES_BLOCK_SIZE];
    int inlen, outlen;
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    if (HMAC_Init_ex(hmac_ctx, key, AES_KEY_SIZE, EVP_sha256(), NULL) != 1) {
        HMAC_CTX_free(hmac_ctx);
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        secure_wipe(key, AES_KEY_SIZE);
        return -1;
    }

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) break;
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) break;
        HMAC_Update(hmac_ctx, outbuf, outlen);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) == 1) {
        fwrite(outbuf, 1, outlen, out);
        HMAC_Update(hmac_ctx, outbuf, outlen);
    }

    unsigned char computed_hmac[HMAC_SIZE];
    HMAC_Final(hmac_ctx, computed_hmac, NULL);

    int valid = memcmp(header.hmac, computed_hmac, HMAC_SIZE) == 0;

    HMAC_CTX_free(hmac_ctx);
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    secure_wipe(key, AES_KEY_SIZE);

    if (!valid) {
        remove(output_file);
        return -1;
    }

    return 0;
}
