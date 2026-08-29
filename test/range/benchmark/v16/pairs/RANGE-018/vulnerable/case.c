typedef __SIZE_TYPE__ size_t;

void *malloc(size_t size);
void free(void *pointer);
void *memcpy(void *restrict destination, const void *restrict source, size_t count);
char *find_character(const char *text, int character);

static void *allocate(size_t size)
{
    return malloc(size);
}

static void note(int value)
{
    (void)value;
}

static char *copy_prefix(const char *message)
{
    char *separator = find_character(message, ':');
    size_t count = (size_t)(separator - message);
    char *copy = allocate(count + 1U);

    if (copy != (void *)0) {
        memcpy(copy, message, count);
        copy[count] = '\0';
        note(separator[1]);
    }

    return copy;
}

int main(void)
{
    char *copy = copy_prefix("plain");
    free(copy);
    return 0;
}
