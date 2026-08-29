typedef unsigned long size_type;

extern void *malloc(size_type size);
extern void free(void *pointer);

typedef void (*release_callback)(void *pointer);

typedef struct {
    int header_pool;
    release_callback release;
} pool_table;

static void *safe_allocate(size_type size)
{
    return malloc(size);
}

static void *header_allocate(size_type size)
{
    unsigned char *base = safe_allocate(size + 8UL);

    if (base == 0) {
        return 0;
    }
    return base + 8UL;
}

static void release_header(void *pointer)
{
    (void)pointer;
}

static void release_node(pool_table *table, void *node)
{
    if (table->header_pool != 0) {
        table->release(node);
    } else {
        free(node);
    }
}

static void anchor(void *pointer)
{
    (void)pointer;
}

int main(void)
{
    pool_table table = {1, release_header};
    void *node = header_allocate(16UL);

    anchor(node);
    if (node != 0) {
        release_node(&table, node);
    }
    return 0;
}
