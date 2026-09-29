#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "vault_crypto.h"

/*
 Current vault file format.
 - New vaults use PBKDF2-HMAC-SHA256 to derive a 256-bit key from the master password then AES-256-GCM to encrypt and authenticate the serialized vault.
 - The fixed header stores the format version, cipher identifiers, PBKDF2 iteration count, salt, and nonce needed to decrypt the file later.
 */
#define VAULT_MAGIC "PMVAULT1"
#define VAULT_MAGIC_SIZE 8
#define VAULT_VERSION 1
#define VAULT_KDF_PBKDF2_SHA256 1
#define VAULT_CIPHER_AES_256_GCM 1
#define PBKDF2_ITERATIONS 600000U
#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32
#define HEADER_SIZE 44

 //Legacy OpenSSL-compatible format retained only so older vaults can still be opened and migrated when they are saved again.
#define LEGACY_MAGIC "Salted__"
#define LEGACY_SALT_SIZE 8
#define LEGACY_IV_SIZE 16

/*
 - Store a 32-bit integer as four big-endian bytes.
 - Using a fixed byte order keeps the on-disk format consistent even when the vault is moved.
 */
static void write_u32_be(unsigned char *destination, uint32_t value) {
    destination[0] = (unsigned char)((value >> 24) & 0xffU);
    destination[1] = (unsigned char)((value >> 16) & 0xffU);
    destination[2] = (unsigned char)((value >> 8) & 0xffU);
    destination[3] = (unsigned char)(value & 0xffU);
}

//Read a 32-bit big-endian integer from the vault header.
static uint32_t read_u32_be(const unsigned char *source) {
    return ((uint32_t)source[0] << 24) |
           ((uint32_t)source[1] << 16) |
           ((uint32_t)source[2] << 8) |
           (uint32_t)source[3];
}

/*
 - Derive a 256-bit AES key from the master password using PBKDF2-HMAC-SHA256.
 - The random salt prevents identical passwords from producing the same key material across different vaults. 
 - The iteration count makes each password guess more expensive.
 */
static VaultCryptoStatus derive_key(const char *password, const unsigned char salt[SALT_SIZE], uint32_t iterations, unsigned char key[KEY_SIZE]) {
    if (password == NULL || salt == NULL || key == NULL || iterations == 0) {
        return VAULT_CRYPTO_CRYPTO_ERROR;
    }

    size_t password_length = strlen(password);
    if (password_length > INT_MAX || iterations > INT_MAX) {
        return VAULT_CRYPTO_CRYPTO_ERROR;
    }

    // Stretch the password into exactly KEY_SIZE bytes of key material.
    if (PKCS5_PBKDF2_HMAC(password, (int)password_length, salt, SALT_SIZE, (int)iterations, EVP_sha256(), KEY_SIZE, key) != 1) {
        return VAULT_CRYPTO_CRYPTO_ERROR;
    }

    return VAULT_CRYPTO_OK;
}

/*
 - Replace the existing vault with a fully written temporary file.
 - Platform specific implementation because Windows provides MoveFileExA(), while POSIX use rename()
 */
static int replace_file(const char *temporary_filename, const char *filename) {
#ifdef _WIN32
    return MoveFileExA(temporary_filename, filename, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(temporary_filename, filename) == 0;
#endif
}

/*
 - Write encrypted vault to disk without writing directly over the old file.
 - The vault is first written as <filename>.tmp in this order: [header][ciphertext][GCM authentication tag]
 - Only after every write, flush, and close succeeds is the old vault replaced.
 */
static VaultCryptoStatus write_vault_file(const char *filename, const unsigned char header[HEADER_SIZE], const unsigned char *ciphertext, size_t ciphertext_length, const unsigned char tag[TAG_SIZE]) {
    size_t filename_length = strlen(filename);
    const char suffix[] = ".tmp";
    char *temporary_filename = malloc(filename_length + sizeof(suffix));
    if (temporary_filename == NULL) {
        return VAULT_CRYPTO_MEMORY_ERROR;
    }

    memcpy(temporary_filename, filename, filename_length);
    memcpy(temporary_filename + filename_length, suffix, sizeof(suffix));

    // Write to temporary file first so a failed save does not destroy old vault.
    FILE *file = fopen(temporary_filename, "wb");
    if (file == NULL) {
        free(temporary_filename);
        return VAULT_CRYPTO_IO_ERROR;
    }

    // Track all three pieces of the file plus the final flush/close operation.
    int write_ok = 1;
    if (fwrite(header, 1, HEADER_SIZE, file) != HEADER_SIZE) {
        write_ok = 0;
    }
    if (write_ok && ciphertext_length > 0 &&
        fwrite(ciphertext, 1, ciphertext_length, file) != ciphertext_length) {
        write_ok = 0;
    }
    if (write_ok && fwrite(tag, 1, TAG_SIZE, file) != TAG_SIZE) {
        write_ok = 0;
    }
    if (fflush(file) != 0) {
        write_ok = 0;
    }
    if (fclose(file) != 0) {
        write_ok = 0;
    }

    if (!write_ok) {
        remove(temporary_filename);
        free(temporary_filename);
        return VAULT_CRYPTO_IO_ERROR;
    }

    // The existing vault is replaced only after temporary file is complete.
    if (!replace_file(temporary_filename, filename)) {
        remove(temporary_filename);
        free(temporary_filename);
        return VAULT_CRYPTO_IO_ERROR;
    }

    free(temporary_filename);
    return VAULT_CRYPTO_OK;
}

/*
 - Encrypt serialized vault data and save it in the current PMVAULT1 format.

 1st Generate a fresh random salt and AES-GCM nonce.
 2nd Build the vault header and derive the AES key from the master password.
 3rd Authenticate the header as Additional Authenticated Data (AAD).
 4th Encrypt the serialized vault with AES-256-GCM.
 5th Retrieve the GCM authentication tag and write the complete vault file.
 6th Wipe sensitive temporary buffers before returning.
 */
VaultCryptoStatus encrypt_data(const unsigned char *plaintext, size_t plaintext_len, const char *password, const char *filename) {
    if (plaintext == NULL || password == NULL || filename == NULL || plaintext_len > INT_MAX) {
        return VAULT_CRYPTO_CRYPTO_ERROR;
    }

    unsigned char header[HEADER_SIZE] = {0};
    unsigned char salt[SALT_SIZE] = {0};
    unsigned char nonce[NONCE_SIZE] = {0};
    unsigned char key[KEY_SIZE] = {0};
    unsigned char tag[TAG_SIZE] = {0};
    unsigned char *ciphertext = NULL;
    EVP_CIPHER_CTX *context = NULL;
    VaultCryptoStatus status = VAULT_CRYPTO_CRYPTO_ERROR;

    // Salt and nonce are public but must be freshly random for every save.
    if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(nonce, NONCE_SIZE) != 1) {
        goto cleanup;
    }

    // Assemble the fixed header.
    memcpy(header, VAULT_MAGIC, VAULT_MAGIC_SIZE);
    header[8] = VAULT_VERSION;
    header[9] = VAULT_KDF_PBKDF2_SHA256;
    header[10] = VAULT_CIPHER_AES_256_GCM;
    header[11] = 0;
    write_u32_be(header + 12, PBKDF2_ITERATIONS);
    memcpy(header + 16, salt, SALT_SIZE);
    memcpy(header + 32, nonce, NONCE_SIZE);

    // Convert the user password into the 256-bit key required by AES-256.
    status = derive_key(password, salt, PBKDF2_ITERATIONS, key);
    if (status != VAULT_CRYPTO_OK) {
        goto cleanup;
    }

    size_t allocation_size;
    if (plaintext_len == 0) {
        allocation_size = 1;
    } else {
        allocation_size = plaintext_len;
    }

    ciphertext = malloc(allocation_size);
    if (ciphertext == NULL) {
        status = VAULT_CRYPTO_MEMORY_ERROR;
        goto cleanup;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        status = VAULT_CRYPTO_MEMORY_ERROR;
        goto cleanup;
    }

    int output_length = 0;
    int final_length = 0;
    int ciphertext_length = 0;

    // The header is authenticated as AAD so changing metadata like the salt, nonce, algorithm identifiers, or iteration count is detected.
    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(context, NULL, &output_length, header, HEADER_SIZE) != 1) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }

    // Encrypt the actual serialized vault payload after registering the AAD.
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(context, ciphertext, &output_length, plaintext, (int)plaintext_len) != 1) {
            status = VAULT_CRYPTO_CRYPTO_ERROR;
            goto cleanup;
        }
        ciphertext_length = output_length;
    }

    if (EVP_EncryptFinal_ex(context, ciphertext + ciphertext_length, &final_length) != 1) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }
    ciphertext_length += final_length;

    // Save the authentication tag. Decryption must verify this tag before the plaintext is accepted as valid.
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }

    status = write_vault_file(filename, header, ciphertext, (size_t)ciphertext_length, tag);

cleanup:
    // Every failure path converges here so allocated OpenSSL state is released and sensitive buffers are wiped consistently.
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (ciphertext != NULL) {
        size_t cleanse_size;
        if (plaintext_len == 0) {
            cleanse_size = 1;
        } else {
            cleanse_size = plaintext_len;
        }
        OPENSSL_cleanse(ciphertext, cleanse_size);
        free(ciphertext);
    }
    OPENSSL_cleanse(key, sizeof(key));
    return status;
}

/*
 - Decrypt a vault stored in the current authenticated PMVAULT1 format.
 - The function validates the header derives the same key from the password and stored salt decrypts the ciphertext and verifies the stored GCM tag.
 - GCM auth is what lets us reject an incorrect password or detect tampering/corruption.
 */
static VaultCryptoStatus decrypt_current_format(FILE *file, long file_size, const char *password, char **plaintext_out) {
    if (file_size < HEADER_SIZE + TAG_SIZE) {
        return VAULT_CRYPTO_CORRUPT;
    }

    unsigned char header[HEADER_SIZE] = {0};
    if (fseek(file, 0, SEEK_SET) != 0 || fread(header, 1, HEADER_SIZE, file) != HEADER_SIZE) {
        return VAULT_CRYPTO_IO_ERROR;
    }

    // Reject unsupported or malformed headers.
    if (memcmp(header, VAULT_MAGIC, VAULT_MAGIC_SIZE) != 0 ||
        header[8] != VAULT_VERSION ||
        header[9] != VAULT_KDF_PBKDF2_SHA256 ||
        header[10] != VAULT_CIPHER_AES_256_GCM) {
        return VAULT_CRYPTO_CORRUPT;
    }

    // Read the stored PBKDF2 work factor
    uint32_t iterations = read_u32_be(header + 12);
    if (iterations < 10000U || iterations > 10000000U) {
        return VAULT_CRYPTO_CORRUPT;
    }

    // Salt and nonce are stored directly in authenticated header.
    const unsigned char *salt = header + 16;
    const unsigned char *nonce = header + 32;
    long ciphertext_length_long = file_size - HEADER_SIZE - TAG_SIZE;
    if (ciphertext_length_long < 0 || ciphertext_length_long > INT_MAX) {
        return VAULT_CRYPTO_CORRUPT;
    }
    int ciphertext_length = (int)ciphertext_length_long;

    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    EVP_CIPHER_CTX *context = NULL;
    unsigned char key[KEY_SIZE] = {0};
    unsigned char tag[TAG_SIZE] = {0};
    VaultCryptoStatus status = VAULT_CRYPTO_CRYPTO_ERROR;

    size_t allocation_size = ciphertext_length == 0 ? 1 : (size_t)ciphertext_length;
    ciphertext = malloc(allocation_size);
    plaintext = malloc((size_t)ciphertext_length + 1U);
    if (ciphertext == NULL || plaintext == NULL) {
        status = VAULT_CRYPTO_MEMORY_ERROR;
        goto cleanup;
    }

    if (ciphertext_length > 0 &&
        fread(ciphertext, 1, (size_t)ciphertext_length, file) != (size_t)ciphertext_length) {
        status = VAULT_CRYPTO_IO_ERROR;
        goto cleanup;
    }
    if (fread(tag, 1, TAG_SIZE, file) != TAG_SIZE) {
        status = VAULT_CRYPTO_IO_ERROR;
        goto cleanup;
    }

    // Recreate same AES key that was used when vault was encrypted.
    status = derive_key(password, salt, iterations, key);
    if (status != VAULT_CRYPTO_OK) {
        goto cleanup;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        status = VAULT_CRYPTO_MEMORY_ERROR;
        goto cleanup;
    }

    int output_length = 0;
    int plaintext_length = 0;

    // Recreate AES-GCM context and authenticate exact header read from disk.
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(context, NULL, &output_length, header, HEADER_SIZE) != 1) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }

    // Decrypt encrypted payload.
    if (ciphertext_length > 0) {
        if (EVP_DecryptUpdate(context, plaintext, &output_length, ciphertext, ciphertext_length) != 1) {
            status = VAULT_CRYPTO_CRYPTO_ERROR;
            goto cleanup;
        }
        plaintext_length = output_length;
    }

    // Tell OpenSSL which auth tag must match during finalization.
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }

    // Failure means either the password-derived key is wrong or some authenticated part of the vault was modified.
    if (EVP_DecryptFinal_ex(context, plaintext + plaintext_length, &output_length) != 1) {
        status = VAULT_CRYPTO_INVALID_PASSWORD;
        goto cleanup;
    }
    plaintext_length += output_length;
    plaintext[plaintext_length] = '\0';

    *plaintext_out = (char *)plaintext;
    plaintext = NULL;
    status = VAULT_CRYPTO_OK;

cleanup:
    // Do not leave decrypted data or key material in buffers on failure.
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, allocation_size);
        free(ciphertext);
    }
    if (plaintext != NULL) {
        OPENSSL_cleanse(plaintext, (size_t)ciphertext_length + 1U);
        free(plaintext);
    }
    OPENSSL_cleanse(key, sizeof(key));
    return status;
}

/*
 Decrypt an older OpenSSL-compatible "Salted__" vault.
 - This path intentionally reproduces the original EVP_BytesToKey + AES-256-CBC behavior only for backwards compatibility.
 - After a legacy vault is successfully opened, the caller can mark it for migration so the next save uses the authenticated PMVAULT1 format.
 */
static VaultCryptoStatus decrypt_legacy_format(FILE *file, long file_size, const char *password, char **plaintext_out) {
    const long legacy_header_size = VAULT_MAGIC_SIZE + LEGACY_SALT_SIZE;
    if (file_size <= legacy_header_size || file_size - legacy_header_size > INT_MAX) {
        return VAULT_CRYPTO_CORRUPT;
    }

    unsigned char magic[VAULT_MAGIC_SIZE];
    unsigned char salt[LEGACY_SALT_SIZE];
    // Legacy files begin with "Salted__" followed by the original 8-byte salt.
    if (fseek(file, 0, SEEK_SET) != 0 ||
        fread(magic, 1, sizeof(magic), file) != sizeof(magic) ||
        memcmp(magic, LEGACY_MAGIC, sizeof(magic)) != 0 ||
        fread(salt, 1, sizeof(salt), file) != sizeof(salt)) {
        return VAULT_CRYPTO_CORRUPT;
    }

    int ciphertext_length = (int)(file_size - legacy_header_size);
    unsigned char *ciphertext = malloc((size_t)ciphertext_length);
    unsigned char *plaintext = malloc((size_t)ciphertext_length + EVP_MAX_BLOCK_LENGTH + 1U);
    EVP_CIPHER_CTX *context = NULL;
    unsigned char key[KEY_SIZE] = {0};
    unsigned char iv[LEGACY_IV_SIZE] = {0};
    VaultCryptoStatus status = VAULT_CRYPTO_CRYPTO_ERROR;

    if (ciphertext == NULL || plaintext == NULL) {
        status = VAULT_CRYPTO_MEMORY_ERROR;
        goto cleanup;
    }

    if (fread(ciphertext, 1, (size_t)ciphertext_length, file) != (size_t)ciphertext_length) {
        status = VAULT_CRYPTO_IO_ERROR;
        goto cleanup;
    }

    // Reproduce the original key and IV derivation exactly so existing vaults remain readable.
    size_t password_length = strlen(password);
    if (password_length > INT_MAX ||
        EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (const unsigned char *)password, (int)password_length, 1, key, iv) == 0) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        status = VAULT_CRYPTO_MEMORY_ERROR;
        goto cleanup;
    }

    int output_length = 0;
    int plaintext_length = 0;
    if (EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(context, plaintext, &output_length, ciphertext, ciphertext_length) != 1) {
        status = VAULT_CRYPTO_CRYPTO_ERROR;
        goto cleanup;
    }
    plaintext_length = output_length;

    // For the legacy CBC bad padding is treated as an invalid password.
    if (EVP_DecryptFinal_ex(context, plaintext + plaintext_length, &output_length) != 1) {
        status = VAULT_CRYPTO_INVALID_PASSWORD;
        goto cleanup;
    }
    plaintext_length += output_length;
    plaintext[plaintext_length] = '\0';

    *plaintext_out = (char *)plaintext;
    plaintext = NULL;
    status = VAULT_CRYPTO_OK;

cleanup:
    // Wipe both the derived key and IV because both are sensitive legacy material.
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, (size_t)ciphertext_length);
        free(ciphertext);
    }
    if (plaintext != NULL) {
        OPENSSL_cleanse(plaintext, (size_t)ciphertext_length + EVP_MAX_BLOCK_LENGTH + 1U);
        free(plaintext);
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return status;
}

/*
 - Open a vault file and dispatch to the correct decryption implementation
 - legacy_format_out is set when an older "Salted__" vault was successfully opened so the application knows it should be upgraded on the next save.
 */
VaultCryptoStatus decrypt_file(const char *filename, const char *password, char **plaintext_out, bool *legacy_format_out) {
    if (filename == NULL || password == NULL || plaintext_out == NULL) {
        return VAULT_CRYPTO_CRYPTO_ERROR;
    }

    *plaintext_out = NULL;
    if (legacy_format_out != NULL) {
        *legacy_format_out = false;
    }

    // ENOENT is handled separately from permission errors and other I/O failures.
    errno = 0;
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        if (errno == ENOENT) {
            return VAULT_CRYPTO_NOT_FOUND;
        }

        return VAULT_CRYPTO_IO_ERROR;
    }

    // Determine the complete file size before parsing so format specific code can validate minimum lengths and calculate the ciphertext size safely.
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return VAULT_CRYPTO_IO_ERROR;
    }
    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return VAULT_CRYPTO_IO_ERROR;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return VAULT_CRYPTO_IO_ERROR;
    }

    unsigned char magic[VAULT_MAGIC_SIZE] = {0};
    if (file_size < VAULT_MAGIC_SIZE || fread(magic, 1, sizeof(magic), file) != sizeof(magic)) {
        fclose(file);
        return VAULT_CRYPTO_CORRUPT;
    }

    // The first eight bytes identify the current format the legacy format or an unknown file.
    VaultCryptoStatus status;
    if (memcmp(magic, VAULT_MAGIC, sizeof(magic)) == 0) {
        status = decrypt_current_format(file, file_size, password, plaintext_out);
    } else if (memcmp(magic, LEGACY_MAGIC, sizeof(magic)) == 0) {
        status = decrypt_legacy_format(file, file_size, password, plaintext_out);
        if (status == VAULT_CRYPTO_OK && legacy_format_out != NULL) {
            *legacy_format_out = true;
        }
    } else {
        status = VAULT_CRYPTO_CORRUPT;
    }

    // A close failure after an otherwise successful read is still treated as an I/O failure.
    if (fclose(file) != 0 && status == VAULT_CRYPTO_OK) {
        if (*plaintext_out != NULL) {
            OPENSSL_cleanse(*plaintext_out, strlen(*plaintext_out));
            free(*plaintext_out);
            *plaintext_out = NULL;
        }
        status = VAULT_CRYPTO_IO_ERROR;
    }

    return status;
}

/*
  - Convert internal crypto/storage status codes into short user-facing messages.
 */
const char *vault_crypto_status_message(VaultCryptoStatus status) {
    switch (status) {
        case VAULT_CRYPTO_OK:
            return "Success.";
        case VAULT_CRYPTO_NOT_FOUND:
            return "Vault file was not found.";
        case VAULT_CRYPTO_INVALID_PASSWORD:
            return "Incorrect password.";
        case VAULT_CRYPTO_CORRUPT:
            return "Vault file is invalid or corrupted.";
        case VAULT_CRYPTO_IO_ERROR:
            return "A file read/write error occurred.";
        case VAULT_CRYPTO_MEMORY_ERROR:
            return "Not enough memory to complete the operation.";
        case VAULT_CRYPTO_CRYPTO_ERROR:
        default:
            return "A cryptographic operation failed.";
    }
}
