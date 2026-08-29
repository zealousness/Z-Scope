extern void *malloc(unsigned long size);
extern void free(void *value);

static void release_value(void *value)
{
    free(value);
}

static void clear_value(int mode)
{
    void *buffer = malloc(1UL);

    if (buffer == (void *)0) {
        return;
    }

    release_value(buffer);

    if (mode > 0) {
        release_value(buffer);
    }
}

int main(void)
{
    clear_value(1);
    return 0;
}
