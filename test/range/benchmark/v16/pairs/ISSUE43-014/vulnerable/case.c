typedef unsigned int count_type;
typedef unsigned long size_type;

void *calloc(size_type, size_type);
void free(void *);

static int next_handle = 1;
static unsigned int live_handles;

static int handle_open(count_type segment, int retry)
{
    if (segment < 4U && retry == 0) {
        ++live_handles;
        return next_handle++;
    }
    return -1;
}

static int process_segments(const char *label, count_type segment_count)
{
    int *handle_table;
    count_type index;

    if (label == (const char *)0) {
        return -1;
    }

    handle_table = (int *)calloc((size_type)segment_count, sizeof(*handle_table));
    if (handle_table == (int *)0) {
        return -1;
    }

    for (index = 0U; index < segment_count; ++index) {
        handle_table[index] = handle_open(index, 0);
        if (handle_table[index] < 0) {
            handle_table[index] = handle_open(index, 1);
        }
    }

    free(handle_table);
    return 0;
}

int main(void)
{
    int result = process_segments("local", 64U);
    return (result == 0 && live_handles != 0U) ? 0 : 1;
}
