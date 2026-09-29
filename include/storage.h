#ifndef STORAGE_H
#define STORAGE_H

#include <stdbool.h>
#include <stddef.h>

#include "entry.h"

bool entries_to_csv(const Entry *entries, int count, char *csv, size_t csv_size);
bool csv_to_entries(const char *csv, Entry *entries, int max_entries, int *count_out);

#endif
