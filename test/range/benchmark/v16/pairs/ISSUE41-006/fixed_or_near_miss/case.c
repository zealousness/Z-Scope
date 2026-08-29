typedef struct {
    int value;
} LocalObject;

typedef union {
    LocalObject object;
    unsigned char bytes[32];
} Storage;

static Storage storage[4];
static int occupied[4];
int active_count = 0;
const int object_limit = 1;

static void *safe_allocate(unsigned long count, unsigned long size)
{
    unsigned long i;
    unsigned long j;

    if (count == 0UL || size == 0UL ||
        count > (unsigned long)sizeof(Storage) / size) {
        return 0;
    }

    for (i = 0UL; i < 4UL; ++i) {
        if (occupied[i] == 0) {
            occupied[i] = 1;
            for (j = 0UL; j < (unsigned long)sizeof(storage[i]); ++j) {
                ((unsigned char *)&storage[i])[j] = 0U;
            }
            return (void *)&storage[i];
        }
    }
    return 0;
}

static int copy_text(const char *source, char **result)
{
    unsigned long length = 0UL;
    unsigned long i;
    char *copy;

    while (source[length] != '\0') {
        ++length;
    }

    copy = safe_allocate(length + 1UL, 1UL);
    if (copy == 0) {
        return -1;
    }

    for (i = 0UL; i <= length; ++i) {
        copy[i] = source[i];
    }
    *result = copy;
    return 0;
}

static void release_memory(void *pointer)
{
    unsigned long i;

    if (pointer == 0) {
        return;
    }

    for (i = 0UL; i < 4UL; ++i) {
        if (pointer == (void *)&storage[i]) {
            occupied[i] = 0;
            return;
        }
    }
}

static int inspect_label(char **slot)
{
    char *value = *slot;

    if (value == 0) {
        return -4;
    }
    return (int)value[0];
}

static int (* volatile label_action)(char **) = inspect_label;

int prepare_context(int mode)
{
    LocalObject *primary;
    char *label = 0;
    int status = -1;

    primary = safe_allocate(1UL, (unsigned long)sizeof(*primary));
    if (primary == 0) {
        return -1;
    }

    if (active_count >= object_limit) {
        status = label_action(&label);
        goto cleanup_all;
    }

    if (copy_text("ok", &label) != 0) {
        status = -2;
        goto cleanup_all;
    }

    if (mode != 0) {
        status = -3;
        goto cleanup_all;
    }

    status = 0;

cleanup_all:
    release_memory(label);
    release_memory(primary);
    return status;
}

int main(void)
{
    return prepare_context(0) != 0;
}
