#include "wiki_demo_api.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

int wiki_parse_port(const char *text, uint16_t *port_out) {
    char *end = NULL;
    long value;

    if (text == NULL || port_out == NULL || text[0] == '\0') {
        return -1;
    }

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < 1024 || value > 65535 || value > USHRT_MAX) {
        return -1;
    }

    *port_out = (uint16_t)value;
    return 0;
}
