#include <stdio.h>
#include <string.h>

#include "entry.h"
#include "storage.h"


// checks whether a field can safely be stored using the program's CSV storage format.
static bool field_is_valid(const char *field) {
    return field != NULL && strchr(field, ',') == NULL && strchr(field, '\n') == NULL && strchr(field, '\r') == NULL;
}


/*
 - Converts an array of Entry structures into comma separated text.
 - Each entry is stored on its own line using the format: site,username,password
 - The CSV data is encrypted before being written to vault.dat.
 */
bool entries_to_csv(const Entry *entries, int count, char *csv, size_t csv_size) {

    if (entries == NULL || csv == NULL || csv_size == 0 || count < 0 || count > MAX_ENTRIES) {
        return false;
    }

    // Tracks how much of the output buffer has already been used.
    size_t used = 0;

    // Start with an empty CSV string.
    csv[0] = '\0';

    for (int i = 0; i < count; i++) {


        // Make sure none of the fields contain characters that would interfere with the simple CSV format.
        if (!field_is_valid(entries[i].site) ||
            !field_is_valid(entries[i].user) ||
            !field_is_valid(entries[i].password)) {
            return false;
        }

        // Append the current entry to the CSV buffer.
        int written = snprintf(csv + used, csv_size - used, "%s,%s,%s\n", entries[i].site, entries[i].user, entries[i].password);
        if (written < 0 || (size_t)written >= csv_size - used) {
            return false;
        }

        // Move the output position forward for the next entry.
        used += (size_t)written;
    }

    return true;
}


/*
Converts decrypted CSV data back into Entry structures.
 Each non-empty line is expected to contain exactly three fields: site,username,password
 The parsed entries are copied into the supplied entries array and the number of successfully loaded entries is returned through count_out.
 */
bool csv_to_entries(const char *csv, Entry *entries, int max_entries, int *count_out) {

    if (csv == NULL || entries == NULL || count_out == NULL || max_entries <= 0) {
        return false;
    }

    int count = 0;

    // line_start points to the beginning of the line currently being parsed.
    const char *line_start = csv;

    while (*line_start != '\0') {

        // Prevent the parser from writing beyond the supplied Entry array.
        if (count >= max_entries) {
            return false;
        }

        // Find the newline marking the end of the current entry.
        const char *line_end = strchr(line_start, '\n');

        size_t line_length;

        if (line_end == NULL) {
            line_length = strlen(line_start);
        } else {
            line_length = (size_t)(line_end - line_start);
        }

        if (line_length == 0) {
            if (line_end == NULL) {
                line_start = line_start + line_length;
            } else {
                line_start = line_end + 1;
            }

            continue;
        }

        // A valid entry cannot exceed the combined maximum size of three fields plus the two commas separating them.
        if (line_length >= (MAX_FIELD * 3U + 2U)) {
            return false;
        }

        /*
         - Copy the current line into a temporary writable buffer.
         - The original CSV pointer is const, so the copied line allows us to replace commas with null terminators while parsing.
         */
        char line[MAX_FIELD * 3 + 2];

        memcpy(line, line_start, line_length);
        line[line_length] = '\0';

        // Find the comma separating the site and username.
        char *first_comma = strchr(line, ',');

        if (first_comma == NULL) {
            return false;
        }

        // Find the comma separating the username and password.
        char *second_comma = strchr(first_comma + 1, ',');

        /*
         - A valid entry must contain exactly two commas.
         - A missing second comma or a third comma means the line is malformed.
         */
        if (second_comma == NULL || strchr(second_comma + 1, ',') != NULL) {
            return false;
        }

        *first_comma = '\0';
        *second_comma = '\0';

        const char *site = line;
        const char *user = first_comma + 1;
        const char *password = second_comma + 1;

        // Determine the length of each field before copying it into an Entry.
        size_t site_length = strlen(site);
        size_t user_length = strlen(user);
        size_t password_length = strlen(password);

         // Each destination field has room for MAX_FIELD bytes including the terminating null character.
        if (site_length >= MAX_FIELD || user_length >= MAX_FIELD || password_length >= MAX_FIELD) {
            return false;
        }

        memcpy(entries[count].site, site, site_length + 1U);
        memcpy(entries[count].user, user, user_length + 1U);
        memcpy(entries[count].password, password, password_length + 1U);

        count++;

        if (line_end == NULL) {
            break;
        }

        // Advance past the newline and begin parsing the next entry.
        line_start = line_end + 1;
    }

    // Give the caller the total number of entries successfully parsed.
    *count_out = count;

    return true;
}