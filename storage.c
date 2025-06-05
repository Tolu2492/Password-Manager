#include <stdio.h>
#include <string.h>
#include "entry.h"
#include "storage.h"

//converting entries to csv
void entries_to_csv(Entry *entries, int count, char *csv, size_t csv_size) {
    csv[0] = '\0';
    for (int i = 0; i < count; i++) {
        char line[400];
        snprintf(line, sizeof(line), "%s,%s,%s\n", entries[i].site, entries[i].user, entries[i].password);
        strncat(csv, line, csv_size - strlen(csv) - 1);
    }
}

//converts csv to entries
int csv_to_entries(const char *csv, Entry *entries, int max_entries) {
    int count = 0;
    const char *line = csv;
    while (*line && count < max_entries) {
        sscanf(line, "%99[^,],%99[^,],%99[^\n]", entries[count].site, entries[count].user, entries[count].password);
        line = strchr(line, '\n');
        if (!line) 
            break;
        line++;
        count++;
    }
    return count;
}
