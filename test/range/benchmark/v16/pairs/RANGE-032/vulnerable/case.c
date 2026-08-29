typedef unsigned int uint32_t;

extern void free(void *pointer);

enum { BUFFER_CAPACITY = 256 };

void release_pointer(void *pointer)
{
    free(pointer);
}

static uint32_t process_line(char *line)
{
    char *value;

    if (line == (char *)0) {
        return 1U;
    }

    value = line;
    while (*value != '\0' && *value != '=') {
        value++;
    }
    if (*value == '\0') {
        return 1U;
    }

    release_pointer(value + 1);
    return 0U;
}

static uint32_t build_line(void)
{
    char line[BUFFER_CAPACITY] = "name=value";

    return process_line(line);
}

int main(void)
{
    return (int)build_line();
}
