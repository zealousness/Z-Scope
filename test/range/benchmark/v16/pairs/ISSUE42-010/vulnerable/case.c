typedef unsigned int uint32_t;

enum { item_capacity = 64u };

uint32_t item_count;

int rebuild_items(uint32_t configured_count)
{
    volatile uint32_t entries[item_capacity];
    uint32_t i;

    item_count = configured_count;
    for (i = 0u; i < item_count; ++i) {
        entries[i] = i;
    }
    (void)entries;
    return 0;
}

int main(void)
{
    return rebuild_items(0u);
}
