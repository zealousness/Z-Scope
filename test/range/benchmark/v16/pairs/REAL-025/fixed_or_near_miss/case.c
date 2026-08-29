typedef struct {
    int value;
} generic_node;

typedef void (*generic_callback)(generic_node *);

typedef struct {
    int lock;
    generic_node node;
} generic_registry;

static generic_registry registry = { 0, { 7 } };
static int observed_lock = -1;
static int observed_value;

static void take_lock(int *lock)
{
    *lock = 1;
}

static void drop_lock(int *lock)
{
    *lock = 0;
}

static generic_node *find_locked(const char *key)
{
    if (key == (const char *)0 || *key == '\0') {
        return (generic_node *)0;
    }
    return &registry.node;
}

static int notify_local(const char *key, generic_callback callback)
{
    generic_node *node;
    generic_callback captured;

    take_lock(&registry.lock);
    node = find_locked(key);
    captured = callback;
    drop_lock(&registry.lock);
    if (node != (generic_node *)0 && captured != (generic_callback)0) {
        captured(node);
    }

    return node != (generic_node *)0 && captured != (generic_callback)0;
}

static void observe(generic_node *node)
{
    observed_lock = registry.lock;
    observed_value = node->value;
}

int main(void)
{
    int result = notify_local("key", observe);

    if (result != 1 || observed_value != 7) {
        return 2;
    }
    return observed_lock;
}
