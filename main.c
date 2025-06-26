
#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "entry.h"
#include "vault_crypto.h"
#include "storage.h"

#define FILENAME "vault.dat"
#define PASSWORD_MAX 128

int main() {
    InitWindow(800, 600, "Password Vault");
    SetTargetFPS(60);

    Entry entries[MAX_ENTRIES];
    int count = 0;
    char password[PASSWORD_MAX] = {0};
    bool vaultLoaded = false;
    bool passwordInputActive = true;
    bool showPassword = false;

    char site[MAX_FIELD] = {0};
    char user[MAX_FIELD] = {0};
    char pass[MAX_FIELD] = {0};

    int selectedEntry = -1;

    bool siteEdit = false;
    bool userEdit = false;
    bool passEdit = false;

    while (!WindowShouldClose()) {
        BeginDrawing();
        ClearBackground(RAYWHITE);

    if (!vaultLoaded) {
        int screenWidth = GetScreenWidth();
        int screenHeight = GetScreenHeight();

        //UI element sizes
        const int textboxWidth = 300;
        const int textboxHeight = 30;
        const int buttonWidth = 80;
        const int buttonHeight = 30;
        const int spacing = 10;

        //Total width of textbox + spacing + button
        int totalWidth = textboxWidth + spacing + buttonWidth;

        //Y-position (centered vertically)
        int centerY = screenHeight / 2;

        //X-position for the textbox
        int startX = (screenWidth - totalWidth) / 2;

        //Prompt text
        const char *prompt = "Enter Vault Password:";
        int promptFontSize = 20;
        int promptWidth = MeasureText(prompt, promptFontSize);

        //Centers the prompt text horizontally above the input box
        DrawText(prompt, (screenWidth - promptWidth) / 2, centerY - 60, promptFontSize, DARKGRAY);

        //password textbox
        Rectangle textboxBounds = { startX, centerY - textboxHeight / 2, textboxWidth, textboxHeight };
        GuiTextBox(textboxBounds, password, PASSWORD_MAX, passwordInputActive);

        //load button next to the textbox
        Rectangle buttonBounds = { startX + textboxWidth + spacing, centerY - buttonHeight / 2, buttonWidth, buttonHeight };
        if (GuiButton(buttonBounds, "Load")) {
            char *decrypted = decrypt_file(FILENAME, password);
            if (decrypted) {
                count = csv_to_entries(decrypted, entries, MAX_ENTRIES);
                free(decrypted);
                vaultLoaded = true;
            } else {
                //else create new vault
                count = 0;
                vaultLoaded = true;
            }
        }
    }else {
            DrawText("Vault Entries", 20, 10, 20, DARKBLUE);

            for (int i = 0; i < count; i++) {
                char buffer[256];
                snprintf(buffer, sizeof(buffer), "%d. %s | %s | %s", i + 1, entries[i].site, entries[i].user, entries[i].password);
                if (GuiButton((Rectangle){20, 40 + i * 35, 600, 30}, buffer)) {
                    selectedEntry = i;
                    strcpy(site, entries[i].site);
                    strcpy(user, entries[i].user);
                    strcpy(pass, entries[i].password);
                    siteEdit = userEdit = passEdit = false;
                }
            }

            if (GuiButton((Rectangle){650, 40, 120, 30}, "Add Entry")) {
                selectedEntry = -1;
                strcpy(site, "");
                strcpy(user, "");
                strcpy(pass, "");
                siteEdit = userEdit = passEdit = false;
            }

            if (GuiButton((Rectangle){650, 80, 120, 30}, "Save Vault")) {
                char csv_data[8192];
                entries_to_csv(entries, count, csv_data, sizeof(csv_data));
                encrypt_data((unsigned char *)csv_data, strlen(csv_data), password, FILENAME);
            }

            if (selectedEntry >= -1) {
                //input fields with separate edit modes
                DrawText("Site Field:", 25, 475, 10, DARKBLUE);
                if (GuiTextBox((Rectangle){20, 500, 200, 30}, site, MAX_FIELD, siteEdit)) {
                    siteEdit = !siteEdit;
                    userEdit = passEdit = false;
                }
                DrawText("User Field:", 245, 475, 10, DARKBLUE);
                if (GuiTextBox((Rectangle){240, 500, 200, 30}, user, MAX_FIELD, userEdit)) {
                    userEdit = !userEdit;
                    siteEdit = passEdit = false;
                }
                DrawText("Password Field:", 465, 475, 10, DARKBLUE);
                if (GuiTextBox((Rectangle){460, 500, 200, 30}, pass, MAX_FIELD, passEdit)) {
                    passEdit = !passEdit;
                    siteEdit = userEdit = false;
                }

                const char* buttonLabel;
                if (selectedEntry == -1) {
                    buttonLabel = "Add";
                } else {
                    buttonLabel = "Update";
                }

                if (GuiButton((Rectangle){680, 500, 100, 30}, buttonLabel)) {
                    if (selectedEntry == -1 && count < MAX_ENTRIES) {
                        strcpy(entries[count].site, site);
                        strcpy(entries[count].user, user);
                        strcpy(entries[count].password, pass);
                        count++;
                    } else if (selectedEntry >= 0) {
                        strcpy(entries[selectedEntry].site, site);
                        strcpy(entries[selectedEntry].user, user);
                        strcpy(entries[selectedEntry].password, pass);
                    }
                    selectedEntry = -1;
                    siteEdit = userEdit = passEdit = false;
                }

                if (selectedEntry >= 0 && GuiButton((Rectangle){680, 540, 100, 30}, "Delete")) {
                    for (int i = selectedEntry; i < count - 1; i++) {
                        entries[i] = entries[i + 1];
                    }
                    count--;
                    selectedEntry = -1;
                    siteEdit = userEdit = passEdit = false;
                }
            }

            //Unfocuses textboxes if mouse is outside any of the fields
            if (IsMouseButtonPressed(MOUSE_LEFT_BUTTON)) {
                Vector2 mouse = GetMousePosition();
                if (!CheckCollisionPointRec(mouse, (Rectangle){20, 500, 200, 30}) &&
                    !CheckCollisionPointRec(mouse, (Rectangle){240, 500, 200, 30}) &&
                    !CheckCollisionPointRec(mouse, (Rectangle){460, 500, 200, 30})) {
                    siteEdit = userEdit = passEdit = false;
                }
            }
        }

        EndDrawing();
    }

    CloseWindow();
    return 0;
}
