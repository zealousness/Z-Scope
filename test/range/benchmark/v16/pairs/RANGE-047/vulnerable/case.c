typedef unsigned long Size;

extern void *calloc(Size count, Size size);
extern void free(void *memory);

enum { STATE_LIVE = 1 };

typedef struct Item Item;

struct Item {
    unsigned state;
    unsigned flags;
    Item *repeat_next;
};

static Item *tree_head;
static Item *repeat_head;
static volatile unsigned result_value;

static void *make_zeroed(Size count, Size size)
{
    return calloc(count, size);
}

static void note(const char *text)
{
    (void)text;
}

static void link_item(Item *item)
{
    if (tree_head == (Item *)0) {
        tree_head = item;
    } else {
        item->repeat_next = repeat_head;
        repeat_head = item;
    }
}

int add_item(unsigned flags)
{
    Item *item = make_zeroed(1UL, sizeof *item);

    if (item == (Item *)0) {
        return -1;
    }

    item->state = STATE_LIVE;
    item->flags = flags;
    link_item(item);

    if (item->flags != 0U) {
        note("rejected");
        free(item);
        return -2;
    }

    return 0;
}

unsigned scan_repeats(void)
{
    unsigned total = 0U;
    Item *cursor = repeat_head;

    while (cursor != (Item *)0) {
        total += cursor->state;
        cursor = cursor->repeat_next;
    }

    return total;
}

int main(void)
{
    (void)add_item(0U);
    (void)add_item(1U);
    result_value = scan_repeats();
    return 0;
}
