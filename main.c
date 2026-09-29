#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

#include <openssl/crypto.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "entry.h"
#include "storage.h"
#include "vault_crypto.h"

#define FILENAME "vault.dat"
#define PASSWORD_MAX 128
#define MESSAGE_MAX 256
#define CSV_BUFFER_SIZE (MAX_ENTRIES * (MAX_FIELD * 3 + 3) + 1)

// Represents the major screens/states the application can display.
typedef enum {
    SCREEN_HOME = 0,
    SCREEN_CREATE,
    SCREEN_UNLOCK,
    SCREEN_VAULT
} AppScreen;

// Securely clears a string buffer that may contain a password.
static void clear_sensitive_string(char *text, size_t size) {
    if (text != NULL && size > 0) {
        OPENSSL_cleanse(text, size);
        text[0] = '\0';
    }
}

// Securely clears an array of vault entries from memory.
// Called when locking the vault and again before the program exits.
static void clear_entries(Entry *entries, int count) {
    if (entries != NULL && count > 0) {
        OPENSSL_cleanse(entries, sizeof(Entry) * (size_t)count);
    }
}

// Checks whether a field can be safely stored by the projects simple CSV format.
static bool field_is_safe_for_csv(const char *text) {
    return text != NULL && strchr(text, ',') == NULL && strchr(text, '\n') == NULL && strchr(text, '\r') == NULL;
}

// Copies a status message into the UI message buffer without overflowing it.
// Passing NULL clears the message
static void set_message(char *message, size_t message_size, const char *text) {
    if (message == NULL || message_size == 0) {
        return;
    }

    if (text == NULL) {
        snprintf(message, message_size, "%s", "");
    } else {
        snprintf(message, message_size, "%s", text);
    }
}

// Draws a line of text horizontally centered in the current application window.
static void draw_centered_text(const char *text, int y, int font_size, Color color) {
    int width = MeasureText(text, font_size);
    DrawText(text, (GetScreenWidth() - width) / 2, y, font_size, color);
}

// Custom password input box used for both master password and entry password fields.
// The return value reports whether the text changed during the current frame.
static bool password_box(Rectangle bounds, char *text, int text_size, bool *active, bool reveal) {
    if (text == NULL || text_size <= 0 || active == NULL) {
        return false;
    }

    bool changed = false;
    Vector2 mouse = GetMousePosition();

    // Clicking inside the rectangle gives this field keyboard focus.
    if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
        *active = CheckCollisionPointRec(mouse, bounds);
    }

    // Only the active password box consumes typed characters and backspace presses.
    if (*active) {
        int character = GetCharPressed();
        while (character > 0) {
            if (character >= 32 && character <= 126) {
                size_t length = strlen(text);
                if (length + 1U < (size_t)text_size) {
                    text[length] = (char)character;
                    text[length + 1U] = '\0';
                    changed = true;
                }
            }
            character = GetCharPressed();
        }

        if (IsKeyPressed(KEY_BACKSPACE)) {
            size_t length = strlen(text);
            if (length > 0) {
                text[length - 1U] = '\0';
                changed = true;
            }
        }
    }

    DrawRectangleRec(bounds, RAYWHITE);

    // Give the active field a thicker blue border so focus is visible to the user.
    float borderThickness;
    Color borderColor;

    if (*active) {
        borderThickness = 2.0f;
        borderColor = DARKBLUE;
    } else {
        borderThickness = 1.0f;
        borderColor = GRAY;
    }

    DrawRectangleLinesEx(bounds, borderThickness, borderColor);

    // Build a separate display string so hiding the password never modifies the real value.
    char display[PASSWORD_MAX] = {0};
    if (reveal) {
        snprintf(display, sizeof(display), "%s", text);
    } else {
        size_t length = strlen(text);
        if (length >= sizeof(display)) {
            length = sizeof(display) - 1U;
        }
        memset(display, '*', length);
        display[length] = '\0';
    }

    DrawText(display, (int)bounds.x + 8, (int)bounds.y + 7, 16, DARKGRAY);
    if (*active) {
        int text_width = MeasureText(display, 16);
        DrawText("|", (int)bounds.x + 8 + text_width, (int)bounds.y + 7, 16, DARKBLUE);
    }

    return changed;
}

// Clears the add/edit form and removes the current entry selection.
static void reset_entry_editor(char *site, char *user, char *pass, int *selected_entry, bool *site_edit, bool *user_edit, bool *pass_edit) {
    site[0] = '\0';
    user[0] = '\0';
    clear_sensitive_string(pass, MAX_FIELD);
    *selected_entry = -1;
    *site_edit = false;
    *user_edit = false;
    *pass_edit = false;
}

// Serializes the in-memory entries to CSV encrypts the CSV and writes vault.dat.
// The temporary plaintext CSV buffer is cleansed before being freed on every path.
static bool save_vault(const Entry *entries, int count, const char *vault_password, char *message, size_t message_size) {
    char *csv_data = calloc(CSV_BUFFER_SIZE, 1U);
    if (csv_data == NULL) {
        set_message(message, message_size, "Unable to allocate memory for the vault.");
        return false;
    }

    if (!entries_to_csv(entries, count, csv_data, CSV_BUFFER_SIZE)) {
        OPENSSL_cleanse(csv_data, CSV_BUFFER_SIZE);
        free(csv_data);
        set_message(message, message_size, "Entry data is too large or contains unsupported commas/newlines.");
        return false;
    }

    // encrypt_data() handles key derivation authenticated encryption and safe file replacement.
    VaultCryptoStatus status = encrypt_data((const unsigned char *)csv_data, strlen(csv_data), vault_password, FILENAME);
    OPENSSL_cleanse(csv_data, CSV_BUFFER_SIZE);
    free(csv_data);

    if (status != VAULT_CRYPTO_OK) {
        set_message(message, message_size, vault_crypto_status_message(status));
        return false;
    }

    set_message(message, message_size, "Vault saved successfully.");
    return true;
}

// Initializes the GUI and runs the application's frame-by-frame state machine.
int main(void) {
    InitWindow(800, 600, "Password Vault");
    SetTargetFPS(60);

    // Decrypted vault entries exist in memory only while the vault is unlocked.
    Entry entries[MAX_ENTRIES] = {0};
    int count = 0;

    AppScreen screen = SCREEN_HOME;
    char vault_password[PASSWORD_MAX] = {0};
    char confirm_password[PASSWORD_MAX] = {0};
    bool password_active = false;
    bool confirm_password_active = false;
    bool legacy_vault_loaded = false;

    // State for the add/update entry editor shown on the vault screen.
    char site[MAX_FIELD] = {0};
    char user[MAX_FIELD] = {0};
    char pass[MAX_FIELD] = {0};
    int selected_entry = -1;
    bool site_edit = false;
    bool user_edit = false;
    bool pass_edit = false;
    bool show_passwords = false;

    // Pagination keeps the vault list readable while still allowing access to every entry.
    const int entriesPerPage = 12;
    int currentPage = 0;
    char message[MESSAGE_MAX] = {0};

    // raylib applications redraw and process input once per frame until the window closes.
    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

        if (screen == SCREEN_HOME) {
            // Home screen detects whether a vault already exists and offers the correct next actions
            draw_centered_text("Password Manager", 145, 32, DARKBLUE);

            bool vault_exists = FileExists(FILENAME);
            const char *vaultMessage;

            if (vault_exists) {
                vaultMessage = "Existing vault.dat detected.";
            } else {
                vaultMessage = "No vault exists yet.";
            }

            draw_centered_text(vaultMessage, 205, 18, DARKGRAY);

            if (GuiButton((Rectangle){280, 270, 240, 42}, "Unlock Vault")) {
                clear_sensitive_string(vault_password, sizeof(vault_password));
                password_active = true;
                screen = SCREEN_UNLOCK;
                set_message(message, sizeof(message), "");
            }

            if (GuiButton((Rectangle){280, 325, 240, 42}, "Create New Vault")) {
                clear_sensitive_string(vault_password, sizeof(vault_password));
                clear_sensitive_string(confirm_password, sizeof(confirm_password));
                password_active = true;
                confirm_password_active = false;
                screen = SCREEN_CREATE;
                set_message(message, sizeof(message), "");
            }

            if (message[0] != '\0') {
                draw_centered_text(message, 400, 16, MAROON);
            }
        } else if (screen == SCREEN_CREATE) {
            // New vaults require a confirmed master password and never overwrite an existing vault.dat.
            draw_centered_text("Create Vault", 120, 30, DARKBLUE);
            draw_centered_text("Choose a master password with at least 8 characters.", 165, 16, DARKGRAY);

            DrawText("Master password", 240, 225, 16, DARKGRAY);
            password_box((Rectangle){240, 250, 320, 34}, vault_password, PASSWORD_MAX, &password_active, false);

            DrawText("Confirm password", 240, 305, 16, DARKGRAY);
            password_box((Rectangle){240, 330, 320, 34}, confirm_password, PASSWORD_MAX, &confirm_password_active, false);

            // Validate the master password before creating and immediately saving an empty vault.
            if (GuiButton((Rectangle){240, 390, 150, 38}, "Create Vault")) {
                if (FileExists(FILENAME)) {
                    set_message(message, sizeof(message), "vault.dat already exists. Unlock it instead; creation will not overwrite it.");
                } else if (strlen(vault_password) < 8U) {
                    set_message(message, sizeof(message), "Master password must be at least 8 characters.");
                } else if (strcmp(vault_password, confirm_password) != 0) {
                    set_message(message, sizeof(message), "The passwords do not match.");
                } else {
                    count = 0;
                    clear_entries(entries, MAX_ENTRIES);

                    if (save_vault(entries, count, vault_password, message, sizeof(message))) {
                        legacy_vault_loaded = false;
                        currentPage = 0;
                        clear_sensitive_string(confirm_password, sizeof(confirm_password));
                        reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                        screen = SCREEN_VAULT;
                    }
                }
            }

            if (GuiButton((Rectangle){410, 390, 150, 38}, "Back")) {
                clear_sensitive_string(vault_password, sizeof(vault_password));
                clear_sensitive_string(confirm_password, sizeof(confirm_password));
                password_active = false;
                confirm_password_active = false;
                screen = SCREEN_HOME;
                set_message(message, sizeof(message), "");
            }

            if (message[0] != '\0') {
                draw_centered_text(message, 455, 15, MAROON);
            }
        } else if (screen == SCREEN_UNLOCK) {
            // Unlocking decrypts vault.dat first, then parses the recovered CSV into Entry structs.
            draw_centered_text("Unlock Vault", 155, 30, DARKBLUE);
            DrawText("Master password", 240, 235, 16, DARKGRAY);
            password_box((Rectangle){240, 260, 320, 34}, vault_password, PASSWORD_MAX, &password_active, false);

            if (GuiButton((Rectangle){240, 325, 150, 38}, "Unlock")) {
                if (!FileExists(FILENAME)) {
                    set_message(message, sizeof(message), "No vault.dat file exists. Create a vault first.");
                } else if (vault_password[0] == '\0') {
                    set_message(message, sizeof(message), "Enter the vault password.");
                } else {
                    char *decrypted = NULL;
                    bool legacy_format = false;
                    VaultCryptoStatus status = decrypt_file(FILENAME, vault_password, &decrypted, &legacy_format);
                    if (status == VAULT_CRYPTO_OK) {
                        // Decryption succeeded. Only replace the active entry count if parsing also succeeds.
                        int loaded_count = 0;
                        if (!csv_to_entries(decrypted, entries, MAX_ENTRIES, &loaded_count)) {
                            set_message(message, sizeof(message), "Vault decrypted, but its contents are malformed or unsupported.");
                        } else {
                            count = loaded_count;
                            legacy_vault_loaded = legacy_format;
                            currentPage = 0;
                            reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                            // A legacy vault remains usable, but the user is prompted to save it so save_vault() rewrites it using the current authenticated format.
                            if (legacy_format) {
                                set_message(message, sizeof(message), "Legacy vault unlocked. Save Vault to upgrade its encryption.");
                            } else {
                                set_message(message, sizeof(message), "Vault unlocked.");
                            }
                            screen = SCREEN_VAULT;
                        }
                        // The decrypted CSV is no longer needed after parsing, so remove it from memory.
                        OPENSSL_cleanse(decrypted, strlen(decrypted));
                        free(decrypted);
                    } else {
                        set_message(message, sizeof(message), vault_crypto_status_message(status));
                    }
                }
            }

            if (GuiButton((Rectangle){410, 325, 150, 38}, "Back")) {
                clear_sensitive_string(vault_password, sizeof(vault_password));
                password_active = false;
                screen = SCREEN_HOME;
                set_message(message, sizeof(message), "");
            }

            if (message[0] != '\0') {
                draw_centered_text(message, 405, 15, MAROON);
            }
        } else if (screen == SCREEN_VAULT) {
            // The unlocked vault screen displays entries and allows add/update/delete/save operations.
            DrawText("Vault Entries", 20, 10, 20, DARKBLUE);

            GuiCheckBox((Rectangle){650, 125, 20, 20}, "Show passwords", &show_passwords);
            // Calculate how many pages are needed. An empty vault still displays as page 1 of 1.
            int totalPages;
            if (count == 0) {
                totalPages = 1;
            } else {
                totalPages = (count + entriesPerPage - 1) / entriesPerPage;
            }
            // Keep the current page valid if entries were added or deleted.
            if (currentPage >= totalPages) {
                currentPage = totalPages - 1;
            }
            if (currentPage < 0) {
                currentPage = 0;
            }

            int startIndex = currentPage * entriesPerPage;
            int endIndex = startIndex + entriesPerPage;
            if (endIndex > count) {
                endIndex = count;
            }
            // Draw only the entries on the current page while keeping each entry's real array index.
            for (int i = startIndex; i < endIndex; i++) {
                char buffer[360];
                const char *display_password;

                // Passwords stay masked in the list unless the user explicitly enables the checkbox.
                if (show_passwords) {
                    display_password = entries[i].password;
                } else {
                    display_password = "********";
                }
                snprintf(buffer, sizeof(buffer), "%d. %s | %s | %s", i + 1, entries[i].site, entries[i].user, display_password);
                // Convert the real entry index into its row position on the current page.
                int displayIndex = i - startIndex;
                // Selecting an entry copies its fields into the editor for possible modification.
                if (GuiButton((Rectangle){20, 40 + displayIndex * 35, 600, 30}, buffer)) {
                    selected_entry = i;
                    snprintf(site, sizeof(site), "%s", entries[i].site);
                    snprintf(user, sizeof(user), "%s", entries[i].user);
                    snprintf(pass, sizeof(pass), "%s", entries[i].password);
                    site_edit = false;
                    user_edit = false;
                    pass_edit = false;
                }
            }

            // Move between pages. Changing pages clears any selection from the previous page.
            if (GuiButton((Rectangle){650, 215, 55, 30}, "Prev")) {
                if (currentPage > 0) {
                    currentPage--;
                    reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                }
            }

            if (GuiButton((Rectangle){715, 215, 55, 30}, "Next")) {
                if (currentPage < totalPages - 1) {
                    currentPage++;
                    reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                }
            }
            char pageText[64];
            snprintf(pageText, sizeof(pageText), "Page %d of %d", currentPage + 1, totalPages);
            DrawText(pageText, 650, 255, 14, DARKGRAY);

            if (GuiButton((Rectangle){650, 40, 120, 30}, "Add Entry")) {
                reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                set_message(message, sizeof(message), "");
            }

            if (GuiButton((Rectangle){650, 80, 120, 30}, "Save Vault")) {
                if (save_vault(entries, count, vault_password, message, sizeof(message))) {
                    legacy_vault_loaded = false;
                }
            }

            // Locking removes decrypted entries passwords and editor contents from memory.
            if (GuiButton((Rectangle){650, 165, 120, 30}, "Lock Vault")) {
                clear_entries(entries, MAX_ENTRIES);
                count = 0;
                clear_sensitive_string(vault_password, sizeof(vault_password));
                clear_sensitive_string(site, sizeof(site));
                clear_sensitive_string(user, sizeof(user));
                clear_sensitive_string(pass, sizeof(pass));
                selected_entry = -1;
                site_edit = false;
                user_edit = false;
                pass_edit = false;
                show_passwords = false;
                legacy_vault_loaded = false;
                currentPage = 0;
                screen = SCREEN_HOME;
                set_message(message, sizeof(message), "Vault locked.");
            }

            DrawText("Site Field:", 25, 475, 10, DARKBLUE);
            if (GuiTextBox((Rectangle){20, 500, 200, 30}, site, MAX_FIELD, site_edit)) {
                site_edit = !site_edit;
                user_edit = false;
                pass_edit = false;
            }

            DrawText("User Field:", 245, 475, 10, DARKBLUE);
            if (GuiTextBox((Rectangle){240, 500, 200, 30}, user, MAX_FIELD, user_edit)) {
                user_edit = !user_edit;
                site_edit = false;
                pass_edit = false;
            }

            DrawText("Password Field:", 465, 475, 10, DARKBLUE);
            password_box((Rectangle){460, 500, 200, 30}, pass, MAX_FIELD, &pass_edit, show_passwords);

            const char *button_label;
            if (selected_entry == -1) {
                button_label = "Add";
            } else {
                button_label = "Update";
            }
            // The same editor handles both new entries and updates to the currently selected entry.
            if (GuiButton((Rectangle){680, 500, 100, 30}, button_label)) {
                if (site[0] == '\0' || user[0] == '\0' || pass[0] == '\0') {
                    set_message(message, sizeof(message), "Site, username, and password are required.");
                } else if (!field_is_safe_for_csv(site) || !field_is_safe_for_csv(user) || !field_is_safe_for_csv(pass)) {
                    set_message(message, sizeof(message), "Fields cannot contain commas or line breaks.");
                } else if (selected_entry == -1) {
                    if (count >= MAX_ENTRIES) {
                        set_message(message, sizeof(message), "Maximum number of entries reached.");
                    } else {
                        snprintf(entries[count].site, MAX_FIELD, "%s", site);
                        snprintf(entries[count].user, MAX_FIELD, "%s", user);
                        snprintf(entries[count].password, MAX_FIELD, "%s", pass);
                        count++;
                        // Move to the page containing the newly added entry.
                        currentPage = (count - 1) / entriesPerPage;
                        reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                        set_message(message, sizeof(message), "Entry added. Save Vault to persist changes.");
                    }
                } else if (selected_entry >= 0 && selected_entry < count) {
                    snprintf(entries[selected_entry].site, MAX_FIELD, "%s", site);
                    snprintf(entries[selected_entry].user, MAX_FIELD, "%s", user);
                    snprintf(entries[selected_entry].password, MAX_FIELD, "%s", pass);
                    reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                    set_message(message, sizeof(message), "Entry updated. Save Vault to persist changes.");
                }
            }

            // Delete by shifting later entries left then cleanse the now unused final slot.
            if (selected_entry >= 0 &&
                GuiButton((Rectangle){680, 540, 100, 30}, "Delete")) {
                for (int i = selected_entry; i < count - 1; i++) {
                    entries[i] = entries[i + 1];
                }
                if (count > 0) {
                    OPENSSL_cleanse(&entries[count - 1], sizeof(Entry));
                    count--;
                    // If the last entry on a page was deleted move back to the last valid page.
                    int updatedTotalPages;
                    if (count == 0) {
                        updatedTotalPages = 1;
                    } else {
                        updatedTotalPages = (count + entriesPerPage - 1) / entriesPerPage;
                    }
                    if (currentPage >= updatedTotalPages) {
                        currentPage = updatedTotalPages - 1;
                    }
                }
                reset_entry_editor(site, user, pass, &selected_entry, &site_edit, &user_edit, &pass_edit);
                set_message(message, sizeof(message), "Entry deleted. Save Vault to persist changes.");
            }

            if (legacy_vault_loaded) {
                DrawText("Legacy encryption detected: save to upgrade.", 480, 15, 13, ORANGE);
            }

            if (message[0] != '\0') {
                Color messageColor;

                if (legacy_vault_loaded) {
                    messageColor = DARKGRAY;
                } else {
                    messageColor = DARKGREEN;
                }

                DrawText(message, 20, 570, 13, messageColor);
            }
        }

        EndDrawing();
    }

    // Final cleanup ensures decrypted credentials and passwords are cleansed before exit.
    clear_entries(entries, MAX_ENTRIES);
    clear_sensitive_string(vault_password, sizeof(vault_password));
    clear_sensitive_string(confirm_password, sizeof(confirm_password));
    clear_sensitive_string(pass, sizeof(pass));

    CloseWindow();
    return 0;
}
