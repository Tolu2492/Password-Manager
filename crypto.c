// crypto.c
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "crypto.h"

#define SALT_SIZE 8
#define KEY_SIZE 32
#define IV_SIZE 16

int encrypt_data(const unsigned char *plaintext, int plaintext_len, const char *password, const char *filename) {
    unsigned char salt[SALT_SIZE];
    if (!RAND_bytes(salt, SALT_SIZE)) {
        fprintf(stderr, "Salt generation failed.\n");
        return 0;
    }

    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        fprintf(stderr, "Key derivation failed.\n");
        return 0;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        return 0;

    int len;
    int ciphertext_len;
    unsigned char *ciphertext = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return 0;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) 
        return 0;
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
        return 0;
    ciphertext_len += len;

    FILE *fp = fopen(filename, "wb");
    fwrite("Salted__", 1, 8, fp);
    fwrite(salt, 1, SALT_SIZE, fp);
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return 1;
}

char *decrypt_file(const char *filename, const char *password) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "[decrypt] Failed to open %s\n", filename);
        return NULL;
    }

    unsigned char header[8];
    unsigned char salt[SALT_SIZE];
    if (fread(header, 1, 8, fp) != 8 || memcmp(header, "Salted__", 8) != 0) {
        fprintf(stderr, "[decrypt] Invalid header (not Salted__)\n");
        fclose(fp);
        return NULL;
    }

    if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
        fprintf(stderr, "[decrypt] Could not read salt\n");
        fclose(fp);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 16, SEEK_SET);

    long ciphertext_len = filesize - 16;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (fread(ciphertext, 1, ciphertext_len, fp) != ciphertext_len) {
        fprintf(stderr, "[decrypt] Failed to read ciphertext\n");
        fclose(fp);
        free(ciphertext);
        return NULL;
    }
    fclose(fp);

    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char *)password, strlen(password), 1, key, iv)) {
        fprintf(stderr, "[decrypt] EVP_BytesToKey failed\n");
        free(ciphertext);
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *plaintext = malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    int len, plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "[decrypt] DecryptInit failed\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "[decrypt] DecryptUpdate failed\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "[decrypt] DecryptFinal failed (likely wrong password or corrupted vault)\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return (char *)plaintext;
}
