#include <stdlib.h>
#include <string.h>
#include "handler.h"

Handler *handler_create(const char *name, handler_fn fn) {
    Handler *h = (Handler *)malloc(sizeof(Handler));
    if (!h) return NULL;
    h->name = name;
    h->process = fn;
    return h;
}

void handler_free(Handler *h) {
    free(h);
}

int dispatch(Handler *h, const char *data, int len) {
    if (!h || !h->process) return -1;
    return h->process(data, len);
}
