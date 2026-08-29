static const unsigned item_limit = 4096u;

static int acquire_item(void)
{
    return 3;
}

static void release_item(int item)
{
    (void)item;
}

static int examine_item(unsigned item_size)
{
    int item = acquire_item();

    if (item < 0) {
        return -1;
    }
    if (item_size > item_limit) {
        return -1;
    }

    release_item(item);
    return 0;
}

int main(void)
{
    return examine_item(4097u) == -1 ? 0 : 1;
}
