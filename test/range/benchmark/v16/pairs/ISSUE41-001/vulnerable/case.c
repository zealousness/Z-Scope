enum {
    maximum_elements = 500u,
    element_width = 48u,
    selected_kind = 1u
};

static const unsigned int cache_limit = 16u * 1024u;
static unsigned char storage[maximum_elements * element_width];

struct task {
    unsigned int kind;
    unsigned int element_count;
};

static void *allocate_zeroed(unsigned int bytes)
{
    unsigned int index;

    if (bytes > (unsigned int)sizeof storage) {
        return 0;
    }
    for (index = 0u; index < bytes; ++index) {
        storage[index] = 0u;
    }
    return storage;
}

static void release_storage(void *memory)
{
    (void)memory;
}

static int prepare_cache(const struct task *value)
{
    unsigned int bytes;
    unsigned int index;
    unsigned char *cache;

    if (value->element_count > maximum_elements) {
        return -1;
    }
    bytes = value->element_count * element_width;
    if (bytes > cache_limit) {
        return -1;
    }
    cache = allocate_zeroed(bytes);
    if (cache == 0) {
        return -1;
    }
    for (index = 0u; index < value->element_count; ++index) {
        cache[index * element_width] = (unsigned char)(index & 255u);
    }
    release_storage(cache);
    return 0;
}

static int dispatch_task(const struct task *value)
{
    if (value->kind == selected_kind) {
        return prepare_cache(value);
    }
    return 0;
}

int main(void)
{
    const struct task value = { selected_kind, maximum_elements };

    return dispatch_task(&value);
}
