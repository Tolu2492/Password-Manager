# Password-Manager
A lightweight password manager written in C
Stores credentials in an AES256 openssl encrypted vault file.
Each entry consists of a site field, username field, and a password field.
# Features:
    - Ability to:
        - Add Entries
        - Update Entries
        - Delete Entries

    - Each entry is added and viewable after each entry completion.

    - Once the entries are saved the vault encrypts and can be reaccessed.
        - To access the vault after saving and exiting reenter the password first used to create the vault.

# Requirements:
OpenSSL library is needed for the password manager to run.

# Instructions: 
1st
    - gcc main.c entry.c crypto.c storage.c -Iinclude -lcrypto -lssl -o password_manager
2nd 
    - ./password_manager

