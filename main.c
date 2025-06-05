#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entry.h"
#include "crypto.h"
#include "storage.h"

#define FILENAME "vault.dat"
#define PASSWORD_MAX 128

#include <sys/stat.h>

//checks if vault exists
int file_exists(const char *filename) {
    struct stat buffer;
    return stat(filename, &buffer) == 0;
}


int main() {
    Entry entries[MAX_ENTRIES];
    int count = 0;

    char password[PASSWORD_MAX];
    printf("Enter vault password: ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
        fprintf(stderr, "Failed to read password.\n");
        return 1;
    }
    password[strcspn(password, "\n")] = 0;

    //decrypts if vault exists
    if (file_exists(FILENAME)) {
        char *decrypted_data = decrypt_file(FILENAME, password);
        if (!decrypted_data) {
            fprintf(stderr, "Failed to decrypt the vault. Password may be incorrect.\n");
            return 1;
        }
        count = csv_to_entries(decrypted_data, entries, MAX_ENTRIES);
        free(decrypted_data);
    } else {
        printf("No vault found. Starting fresh.\n");
    }

//Vault Menus
while (1) {
    printf("\n--- Vault Entries ---\n");
    for (int i = 0; i < count; i++) {
        printf("%d. Site: %s | User: %s | Pass: %s\n", i + 1, entries[i].site, entries[i].user, entries[i].password);
    }

    printf("\nChoose an action:\n");
    printf("1. Add Entry\n2. Edit Entry\n3. Delete Entry\n4. Save and Exit\n> ");
    int choice;
    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid input.\n");
        break;
    }
    getchar();

        switch (choice) {
            case 1:
                if (count < MAX_ENTRIES) {
                    Entry new_entry;
                    printf("Enter site: "); fgets(new_entry.site, MAX_FIELD, stdin); new_entry.site[strcspn(new_entry.site, "\n")] = 0;
                    printf("Enter user: "); fgets(new_entry.user, MAX_FIELD, stdin); new_entry.user[strcspn(new_entry.user, "\n")] = 0;
                    printf("Enter pass: "); fgets(new_entry.password, MAX_FIELD, stdin); new_entry.password[strcspn(new_entry.password, "\n")] = 0;
                    entries[count++] = new_entry;
                } else {
                    printf("Entry limit reached.\n");
                }
                break;

            case 2: {
                int index;
                printf("Enter entry number to edit: "); 
                if (scanf("%d", &index) == 1) {
                    getchar();
                    if (index >= 1 && index <= count) {
                        index--;
                        printf("Edit site: "); fgets(entries[index].site, MAX_FIELD, stdin); entries[index].site[strcspn(entries[index].site, "\n")] = 0;
                        printf("Edit user: "); fgets(entries[index].user, MAX_FIELD, stdin); entries[index].user[strcspn(entries[index].user, "\n")] = 0;
                        printf("Edit pass: "); fgets(entries[index].password, MAX_FIELD, stdin); entries[index].password[strcspn(entries[index].password, "\n")] = 0;
                    } else {
                        printf("Invalid entry number.\n");
                    }
                } else {
                    getchar();
                    printf("Invalid input.\n");
                }
                break;
            }

            case 3: {
                int index;
                printf("Enter entry number to delete: ");
                if (scanf("%d", &index) == 1) {
                    getchar();
                    if (index >= 1 && index <= count) {
                        for (int i = index - 1; i < count - 1; i++) {
                            entries[i] = entries[i + 1];
                        }
                        count--;
                    } else {
                        printf("Invalid entry number.\n");
                    }
                } else {
                    getchar();
                    printf("Invalid input.\n");
                }
                break;
            }

            case 4: {
                char csv_data[MAX_ENTRIES * 400];
                entries_to_csv(entries, count, csv_data, sizeof(csv_data));
                if (encrypt_data((unsigned char *)csv_data, strlen(csv_data), password, FILENAME)) {
                    printf("Vault updated and saved.\n");
                } else {
                    fprintf(stderr, "Failed to save the vault.\n");
                }
                return 0;
            }

            default:
                printf("Invalid choice.\n");
                break;
        }
    }


    return 0;
}
