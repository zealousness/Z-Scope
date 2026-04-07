#ifndef HANDLER_H
#define HANDLER_H

typedef int (*handler_fn)(const char *data, int len);

typedef struct {
    const char *name;
    handler_fn  process;
} Handler;

Handler *handler_create(const char *name, handler_fn fn);
void     handler_free(Handler *h);
int      dispatch(Handler *h, const char *data, int len);

#endif
