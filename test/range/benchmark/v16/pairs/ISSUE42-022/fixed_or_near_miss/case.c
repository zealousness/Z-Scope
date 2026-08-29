typedef unsigned long size_type;

void *malloc(size_type size);
void free(void *pointer);

typedef struct
{
    void *anchor;
    void *buffer;
} LocalInfo;

static void *safe_allocate(size_type size)
{
    return malloc(size);
}

static void safe_release(void **pointer)
{
    if (*pointer != (void *)0)
    {
        free(*pointer);
        *pointer = (void *)0;
    }
}

static int clean_local(void *anchor)
{
    LocalInfo info;

    info.anchor = anchor;
    info.buffer = safe_allocate(1UL);
    if (info.buffer == (void *)0)
    {
        return 0;
    }
    if (info.anchor == (void *)0)
    {
        safe_release(&info.buffer);
        return 0;
    }
    safe_release(&info.buffer);
    return 0;
}

int main(void)
{
    return clean_local((void *)0);
}
