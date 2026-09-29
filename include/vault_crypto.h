#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    VAULT_CRYPTO_OK = 0,
    VAULT_CRYPTO_NOT_FOUND,
    VAULT_CRYPTO_INVALID_PASSWORD,
    VAULT_CRYPTO_CORRUPT,
    VAULT_CRYPTO_IO_ERROR,
    VAULT_CRYPTO_MEMORY_ERROR,
    VAULT_CRYPTO_CRYPTO_ERROR
} VaultCryptoStatus;

VaultCryptoStatus encrypt_data(const unsigned char *plaintext,
                               size_t plaintext_len,
                               const char *password,
                               const char *filename);

VaultCryptoStatus decrypt_file(const char *filename,
                               const char *password,
                               char **plaintext_out,
                               bool *legacy_format_out);

const char *vault_crypto_status_message(VaultCryptoStatus status);

#endif
