typedef unsigned long size_t;

enum { RETRY_LATER = 1, RETRY_INTERRUPTED = 2 };

static int errno;
static int script_values[8];
static int script_errors[8];
static size_t script_length;
static size_t script_cursor;

static int read_step(unsigned char *buffer, size_t capacity)
{
    size_t index;

    (void)buffer;
    (void)capacity;
    if (script_length == 0u) {
        errno = 0;
        return 0;
    }
    index = script_cursor < script_length
        ? script_cursor
        : script_length - 1u;
    if (script_cursor < script_length) {
        script_cursor += 1u;
    }
    errno = script_errors[index];
    return script_values[index];
}

static int collect_bytes(unsigned char *buffer, size_t wanted)
{
    size_t received = 0u;
    size_t retries = 3u;

    while (received < wanted) {
        int amount;

        do {
            amount = read_step(buffer + received, wanted - received);
            if (amount < 0 && (errno == RETRY_LATER || errno == RETRY_INTERRUPTED)) {
                if (retries == 0u) {
                    return -1;
                }
                retries -= 1u;
            }
        } while (amount < 0 && (errno == RETRY_LATER || errno == RETRY_INTERRUPTED));
        if (amount <= 0) {
            return -1;
        }
        received += (size_t)amount;
    }
    return 0;
}

int main(void)
{
    unsigned char buffer[1] = { 0u };

    script_values[0] = 1;
    script_errors[0] = 0;
    script_length = 1u;
    script_cursor = 0u;
    return collect_bytes(buffer, sizeof buffer);
}
