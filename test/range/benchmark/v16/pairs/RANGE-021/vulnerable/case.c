typedef struct {
    int key;
    int ref_count;
} LifecycleEntry;

typedef struct {
    int lock;
    LifecycleEntry entry;
    int present;
} LifecycleState;

static LifecycleState g_lifecycle = { 0, { 1, 1 }, 1 };

static void enter_guard(int *lock)
{
    *lock = 1;
}

static void leave_guard(int *lock)
{
    *lock = 0;
}

static LifecycleEntry *lookup(int key)
{
    if (g_lifecycle.present != 0 && g_lifecycle.entry.key == key) {
        return &g_lifecycle.entry;
    }
    return (LifecycleEntry *)0;
}

static void remove_entry(int key)
{
    enter_guard(&g_lifecycle.lock);
    if (g_lifecycle.present != 0 && g_lifecycle.entry.key == key) {
        g_lifecycle.present = 0;
    }
    leave_guard(&g_lifecycle.lock);
}

static int acquire_ref(int key)
{
    LifecycleEntry *entry;

    enter_guard(&g_lifecycle.lock);
    entry = lookup(key);
    leave_guard(&g_lifecycle.lock);
    if (entry == (LifecycleEntry *)0) {
        return 0;
    }
    entry->ref_count += 1;
    return entry->ref_count;
}

static int release_ref(int key)
{
    LifecycleEntry *entry;
    int count;

    enter_guard(&g_lifecycle.lock);
    entry = lookup(key);
    leave_guard(&g_lifecycle.lock);
    if (entry == (LifecycleEntry *)0) {
        return 0;
    }
    entry->ref_count -= 1;
    count = entry->ref_count;
    if (count == 0) {
        remove_entry(key);
    }
    return count;
}

int main(void)
{
    int first = acquire_ref(1);
    int second = release_ref(1);
    int third = release_ref(1);

    return (first == 2 && second == 1 && third == 0) ? 0 : 1;
}
