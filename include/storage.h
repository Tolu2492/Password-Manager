#ifndef STORAGE_H
#define STORAGE_H

#include "entry.h"

void entries_to_csv(Entry *entries, int count, char *csv, size_t csv_size);
int csv_to_entries(const char *csv, Entry *entries, int max_entries);

#endif
