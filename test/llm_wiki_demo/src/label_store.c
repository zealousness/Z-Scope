#include "wiki_demo_api.h"

#include <stddef.h>
#include <string.h>

#define LABEL_CAPACITY 32

int wiki_copy_label(const char *label) {
    char stored_label[LABEL_CAPACITY];
    size_t label_len;
    size_t index;

    if (label == NULL) {
        return -1;
    }

    label_len = strlen(label);

    for (index = 0; index < label_len; ++index) {
        stored_label[index] = label[index];
    }
    stored_label[label_len] = '\0';

    return stored_label[0] == '\0' ? 0 : 1;
}
