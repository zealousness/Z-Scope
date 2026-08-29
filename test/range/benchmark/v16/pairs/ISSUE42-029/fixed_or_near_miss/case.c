typedef struct {
    int done;
} ItemBase;

typedef struct {
    ItemBase base;
    int release_in_callback;
    int payload;
} Item;

typedef struct {
    int held;
} LocalLock;

extern void *malloc(unsigned long size);
extern void free(void *pointer);

static Item *active_item;
static LocalLock active_lock;

static void lock_enter(LocalLock *lock)
{
    lock->held = 1;
}

static void lock_leave(LocalLock *lock)
{
    lock->held = 0;
}

static Item *allocate_item(void)
{
    Item *item = (Item *)malloc(sizeof(*item));
    if (item != 0) {
        item->base.done = 0;
        item->release_in_callback = 0;
        item->payload = 1;
    }
    return item;
}

static void safe_release(Item **item)
{
    if (*item != 0) {
        free(*item);
        *item = 0;
    }
}

static int completion_callback(Item *item)
{
    item->base.done = 1;
    return 1;
}

static void finish_current_item(Item *item)
{
    (void)completion_callback(item);
    item->payload = 0;
    lock_enter(&active_lock);
    if (active_item == item) {
        active_item = 0;
    }
    lock_leave(&active_lock);
    safe_release(&item);
}

static void dispatch_item_cycle(void)
{
    Item *item;

    lock_enter(&active_lock);
    item = active_item;
    lock_leave(&active_lock);

    if (item != 0) {
        finish_current_item(item);
    }
}

static int schedule_item(int release_in_callback)
{
    Item *item = allocate_item();
    if (item == 0) {
        return 0;
    }

    item->release_in_callback = release_in_callback;
    lock_enter(&active_lock);
    active_item = item;
    lock_leave(&active_lock);
    dispatch_item_cycle();
    return 1;
}

int main(void)
{
    return schedule_item(1) == 1 ? 0 : 1;
}
