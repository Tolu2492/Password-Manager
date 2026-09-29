# Password Manager

A lightweight desktop password vault written in C with raylib/raygui for the interface and OpenSSL for cryptography.

## Recent Changes

- Separate **Create Vault** and **Unlock Vault** flows.
- Master password fields are masked.
- Stored passwords are hidden by default and can be revealed with the Show passwords checkbox.
- New vaults use PBKDF2-HMAC-SHA256 to derive an AES-256 key.
- Vault contents use AES-256-GCM authenticated encryption.
- Existing legacy `Salted__` AES-256-CBC vaults created by earlier versions can still be opened. Saving the vault rewrites it in the new authenticated format.
- Vault writes use a temporary file and replace the old vault only after a successful write.

## Features

- Create and unlock an encrypted local vault
- Add, update, and delete credentials
- Hide/reveal stored passwords
- Lock the vault without closing the application
- Authenticated encrypted storage in `vault.dat`
- Automatic migration from the original vault format after a successful save

## Build prerequisites

- CMake 3.20+
- A C11 compiler
- OpenSSL 3.x development package
- Git, if CMake needs to fetch raylib automatically

raygui is included as a header in this repository. CMake first looks for an installed raylib 5.x package. If one is not found, it fetches the pinned raylib 5.5 source automatically.

### Windows example with vcpkg

Install OpenSSL for your target architecture, then configure CMake with the vcpkg toolchain:

```powershell
vcpkg install openssl:x64-windows
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The executable is named `PasswordManager` (`PasswordManager.exe` on Windows).

### Linux example

Install the OpenSSL development package with your distribution's package manager, then run:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```


## Tests

The repository includes crypto/storage tests covering a successful encryption round trip, wrong-password rejection, ciphertext tamper detection, missing-vault handling, and storage serialization.

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Vault behavior

`vault.dat` is created in the application's current working directory. Creating a new vault refuses to overwrite an existing `vault.dat`. To start over intentionally, first move or delete the old vault yourself.
