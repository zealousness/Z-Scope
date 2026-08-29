typedef unsigned long size_type;

extern void *calloc(size_type count, size_type size);
extern void free(void *pointer);

typedef struct Record {
    char *value;
} Record;

static void *make_zeroed(size_type count, size_type size)
{
    return calloc(count, size);
}

static void copy_chars(char *destination, const char *source)
{
    while (*source != '\0') {
        *destination++ = *source++;
    }
    *destination = '\0';
}

static char *clone_chars(const char *source)
{
    size_type length = 0;
    char *copy;

    while (source[length] != '\0') {
        ++length;
    }
    copy = make_zeroed(length + 1, 1);
    if (copy != (char *)0) {
        copy_chars(copy, source);
    }
    return copy;
}

static void clear_chars(char **slot)
{
    free(*slot);
    *slot = (char *)0;
}

static void inspect_chars(const char *text)
{
    volatile unsigned char checksum = 0;

    while (*text != '\0') {
        checksum = (unsigned char)(checksum ^ (unsigned char)*text++);
    }
    (void)checksum;
}

static void receive(void *context)
{
    Record *record = context;

    if (record->value != (char *)0) {
        inspect_chars(record->value);
    }
}

static void dispatch(void (*callback)(void *), void *context)
{
    callback(context);
}

static void execute_case(void)
{
    Record *record = make_zeroed(1, sizeof(*record));
    char *local_value;

    if (record == (Record *)0) {
        return;
    }
    local_value = clone_chars("entry");
    if (local_value == (char *)0) {
        free(record);
        return;
    }
    record->value = local_value;
    clear_chars(&local_value);
    dispatch(receive, record);
    free(record);
}

int main(void)
{
    execute_case();
    return 0;
}
