typedef unsigned long Size;

void *malloc(Size size);
void free(void *pointer);

typedef struct Item {
    void *payload;
    char *name;
    struct Item *next;
} Item;

static Item *registry_root;
static int lock_state;

static void acquire_lock(void)
{
    lock_state = 1;
}

static void release_lock(void)
{
    lock_state = 0;
}

static void safe_free(void *pointer)
{
    if (pointer != (void *)0) {
        free(pointer);
    }
}

static Item *allocate_item(void)
{
    Item *item = malloc(sizeof(*item));

    if (item == (void *)0) {
        return (void *)0;
    }

    item->payload = malloc(8UL);
    if (item->payload == (void *)0) {
        safe_free(item);
        return (void *)0;
    }

    item->name = malloc(8UL);
    if (item->name == (void *)0) {
        safe_free(item->payload);
        safe_free(item);
        return (void *)0;
    }

    item->next = (void *)0;
    return item;
}

static void insert_locked(Item *item)
{
    item->next = registry_root;
    registry_root = item;
}

static void remove_locked(Item *item)
{
    if (registry_root == item) {
        registry_root = item->next;
    }
}

static int perform_update(int removal_status)
{
    Item *node = allocate_item();

    if (node == (void *)0) {
        return -1;
    }

    acquire_lock();
    insert_locked(node);
    release_lock();

    acquire_lock();
    remove_locked(node);
    release_lock();

    if (removal_status != 0) {
        return -1;
    }

    safe_free(node->payload);
    safe_free(node->name);
    safe_free(node);
    return 0;
}

int main(void)
{
    return perform_update(1) == -1 ? 0 : 1;
}
