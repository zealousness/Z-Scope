#include <stdlib.h>

int neutral_resource(void) {
    void *handle = malloc(16);
    if (handle == NULL) {
        return -1;
    }
    free(handle);
    return 0;
}
