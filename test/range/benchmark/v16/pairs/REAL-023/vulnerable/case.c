struct Item {
    int value;
};

static int lock_depth;
static struct Item item_storage;

static void lock_item(int *state)
{
    *state += 1;
}

static void unlock_item(int *state)
{
    *state -= 1;
}

static void safe_release(struct Item **item)
{
    *item = (struct Item *)0;
}

static struct Item *allocate_item(int fail)
{
    if (fail != 0) {
        return (struct Item *)0;
    }
    return &item_storage;
}

static int wrapper(int fail)
{
    struct Item *item;

    lock_item(&lock_depth);
    item = allocate_item(fail);
    if (item == (struct Item *)0) {
        return -1;
    }

    safe_release(&item);
    unlock_item(&lock_depth);
    return 0;
}

int main(void)
{
    return wrapper(1);
}
