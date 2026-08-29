typedef unsigned long size_type;

static unsigned char special_value;
static unsigned char regular_value;

static int is_character_mode(int mode)
{
    return mode == 1;
}

static void *select_value(int mode, size_type file_size, size_type map_size)
{
    if (!is_character_mode(mode) && file_size < map_size) {
        return (void *)0;
    }

    if (is_character_mode(mode)) {
        return &special_value;
    }

    return &regular_value;
}

int main(void)
{
    void *result = select_value(1, 0UL, 1UL);
    return result == (void *)0;
}
