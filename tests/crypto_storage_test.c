#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "entry.h"
#include "storage.h"
#include "vault_crypto.h"

#define TEST_FILE "password_manager_test_vault.dat"
#define CHECK(condition) do {if (!(condition)) {fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); exit(EXIT_FAILURE);} } while (0)

// tests if old version vault.dat created from prev version of password manager can still be opened
static void write_legacy_vault(const char *plaintext, const char *password) {
    unsigned char salt[8];
    unsigned char key[32];
    unsigned char iv[16];
    CHECK(RAND_bytes(salt, sizeof(salt)) == 1);
    CHECK(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (const unsigned char *)password, (int)strlen(password), 1, key, iv) != 0);

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    CHECK(context != NULL);
    CHECK(EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, key, iv) == 1);

    size_t plaintext_length = strlen(plaintext);
    unsigned char *ciphertext = malloc(plaintext_length + EVP_MAX_BLOCK_LENGTH);
    CHECK(ciphertext != NULL);

    int output_length = 0;
    int ciphertext_length = 0;
    CHECK(EVP_EncryptUpdate(context, ciphertext, &output_length, (const unsigned char *)plaintext, (int)plaintext_length) == 1);
    ciphertext_length = output_length;

    CHECK(EVP_EncryptFinal_ex(context, ciphertext + ciphertext_length, &output_length) == 1);
    ciphertext_length += output_length;

    FILE *file = fopen(TEST_FILE, "wb");
    CHECK(file != NULL);
    CHECK(fwrite("Salted__", 1, 8, file) == 8);
    CHECK(fwrite(salt, 1, sizeof(salt), file) == sizeof(salt));
    CHECK(fwrite(ciphertext, 1, (size_t)ciphertext_length, file) == (size_t)ciphertext_length);
    CHECK(fclose(file) == 0);

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(ciphertext, plaintext_length + EVP_MAX_BLOCK_LENGTH);
    free(ciphertext);
    EVP_CIPHER_CTX_free(context);
}
//tests whether entries can be converted to CSV and back without losing data
static void test_storage_round_trip(void) {
    Entry source[2] = {
        {"example.com", "alice", "one-secret"},
        {"example.org", "bob", "two-secret"}
    };
    char csv[1024] = {0};
    CHECK(entries_to_csv(source, 2, csv, sizeof(csv)));

    Entry loaded[MAX_ENTRIES] = {0};
    int count = 0;
    CHECK(csv_to_entries(csv, loaded, MAX_ENTRIES, &count));
    CHECK(count == 2);
    CHECK(strcmp(loaded[0].site, source[0].site) == 0);
    CHECK(strcmp(loaded[1].password, source[1].password) == 0);

    strcpy(source[0].site, "bad,site");
    CHECK(!entries_to_csv(source, 2, csv, sizeof(csv)));
}
//testing encrypt and decrypt path.
static void test_crypto_round_trip(void) {
    const char *plaintext = "example.com,alice,secret\n";
    const char *password = "correct horse battery staple";

    remove(TEST_FILE);
    CHECK(encrypt_data((const unsigned char *)plaintext, strlen(plaintext), password, TEST_FILE) == VAULT_CRYPTO_OK);

    char *decrypted = NULL;
    bool legacy = true;
    CHECK(decrypt_file(TEST_FILE, password, &decrypted, &legacy) == VAULT_CRYPTO_OK);
    CHECK(decrypted != NULL);
    CHECK(!legacy);
    CHECK(strcmp(decrypted, plaintext) == 0);
    OPENSSL_cleanse(decrypted, strlen(decrypted));
    free(decrypted);

    decrypted = NULL;
    CHECK(decrypt_file(TEST_FILE, "wrong password", &decrypted, NULL) == VAULT_CRYPTO_INVALID_PASSWORD);
    CHECK(decrypted == NULL);
}
//tests whether new vault format can detect when the encrypted file has been modified
static void test_tamper_detection(void) {
    FILE *file = fopen(TEST_FILE, "r+b");
    CHECK(file != NULL);
    CHECK(fseek(file, -1L, SEEK_END) == 0);
    int byte = fgetc(file);
    CHECK(byte != EOF);
    CHECK(fseek(file, -1L, SEEK_CUR) == 0);
    CHECK(fputc(byte ^ 0x01, file) != EOF);
    CHECK(fclose(file) == 0);

    char *decrypted = NULL;
    VaultCryptoStatus status = decrypt_file(TEST_FILE, "correct horse battery staple", &decrypted, NULL);
    CHECK(status == VAULT_CRYPTO_INVALID_PASSWORD);
    CHECK(decrypted == NULL);
}

static void test_legacy_compatibility(void) {
    const char *plaintext = "legacy.example,legacy-user,legacy-secret\n";
    const char *password = "legacy password";
    write_legacy_vault(plaintext, password);

    char *decrypted = NULL;
    bool legacy = false;
    CHECK(decrypt_file(TEST_FILE, password, &decrypted, &legacy) == VAULT_CRYPTO_OK);
    CHECK(decrypted != NULL);
    CHECK(legacy);
    CHECK(strcmp(decrypted, plaintext) == 0);
    OPENSSL_cleanse(decrypted, strlen(decrypted));
    free(decrypted);
}

static void test_missing_file(void) {
    remove(TEST_FILE);
    char *decrypted = NULL;
    CHECK(decrypt_file(TEST_FILE, "password", &decrypted, NULL) == VAULT_CRYPTO_NOT_FOUND);
    CHECK(decrypted == NULL);
}

int main(void) {
    test_storage_round_trip();
    test_crypto_round_trip();
    test_tamper_detection();
    test_legacy_compatibility();
    test_missing_file();
    puts("All password manager crypto/storage tests passed.");
    return EXIT_SUCCESS;
}
