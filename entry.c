#include <stdio.h>
#include <string.h>
#include "entry.h"

void add_entry(Entry *entries, int *count) {
    if (*count >= MAX_ENTRIES) {
        printf("Max entries reached.\n");
        return;
    }
    printf("Enter site: ");
    scanf("%s", entries[*count].site);
    printf("Enter username: ");
    scanf("%s", entries[*count].user);
    printf("Enter password: ");
    scanf("%s", entries[*count].password);
    (*count)++;
}

void list_entries(Entry *entries, int count) {
    for (int i = 0; i < count; i++) {
        printf("%d. %s | %s | %s\n", i + 1, entries[i].site, entries[i].user, entries[i].password);
    }
}

void edit_entry(Entry *entries, int count) {
    int index;
    list_entries(entries, count);
    printf("Select entry to edit (1-%d): ", count);
    scanf("%d", &index);
    index--;
    if (index < 0 || index >= count) {
        printf("Invalid entry.\n");
        return;
    }
    printf("Enter new site: ");
    scanf("%s", entries[index].site);
    printf("Enter new username: ");
    scanf("%s", entries[index].user);
    printf("Enter new password: ");
    scanf("%s", entries[index].password);
}

void delete_entry(Entry *entries, int *count) {
    int index;
    list_entries(entries, *count);
    printf("Select entry to delete (1-%d): ", *count);
    scanf("%d", &index);
    index--;
    if (index < 0 || index >= *count) {
        printf("Invalid entry.\n");
        return;
    }
    for (int i = index; i < *count - 1; i++) {
        entries[i] = entries[i + 1];
    }
    (*count)--;
}
