#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#define KEY_LEN 32
#define IV_LEN 16
#define SALT_LEN 16

int encrypt_data(const unsigned char *plaintext, int plaintext_len, const char *password, const char *filename);
char *decrypt_file(const char *filename, const char *password);


#endif
