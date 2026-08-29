typedef unsigned int uint32_t;
typedef unsigned long size_type;

void *malloc(size_type size);
void free(void *pointer);

int release_cursor(uint32_t flags)
{
    unsigned char *base = malloc(32u);
    unsigned char *cursor = base;

    if (base == (void *)0) {
        return -1;
    }
    if ((flags & 1u) != 0u) {
        cursor += 16u;
    }
    (void)cursor;
    free(base);
    return 0;
}

int main(void)
{
    return 0;
}
