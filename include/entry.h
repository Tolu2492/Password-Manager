#ifndef ENTRY_H
#define ENTRY_H

#define MAX_ENTRIES 100
#define MAX_FIELD 100

typedef struct {
    char site[MAX_FIELD];
    char user[MAX_FIELD];
    char password[MAX_FIELD];
} Entry;

void add_entry(Entry *entries, int *count);
void edit_entry(Entry *entries, int count);
void delete_entry(Entry *entries, int *count);
void list_entries(Entry *entries, int count);

#endif
