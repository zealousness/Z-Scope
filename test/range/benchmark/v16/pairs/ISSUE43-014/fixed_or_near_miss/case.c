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

static void handle_release(int handle)
{
    if (handle >= 0 && live_handles != 0U) {
        --live_handles;
    }
}

static int process_segments(const char *label, count_type segment_count)
{
    const count_type segment_limit = 16U;
    int *handle_table;
    count_type index;
    count_type opened = 0U;
    int result = 0;

    if (label == (const char *)0 || segment_count > segment_limit) {
        return -1;
    }

    handle_table = (int *)calloc((size_type)segment_count, sizeof(*handle_table));
    if (handle_table == (int *)0) {
        return -1;
    }

    for (index = 0U; index < segment_count; ++index) {
        int handle = handle_open(index, 0);
        if (handle < 0) {
            handle = handle_open(index, 1);
        }
        if (handle < 0) {
            result = -1;
            break;
        }
        handle_table[opened] = handle;
        ++opened;
    }

    while (opened != 0U) {
        --opened;
        handle_release(handle_table[opened]);
    }
    free(handle_table);
    return result;
}

int main(void)
{
    int result = process_segments("local", 64U);
    return (result != 0 && live_handles == 0U) ? 0 : 1;
}
