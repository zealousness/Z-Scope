typedef void (*choice_fn)(const unsigned char **, int, const unsigned char *, unsigned long, const unsigned char *);

static void choose(const unsigned char **slot, int fail_open,
                   const unsigned char *wire, unsigned long wire_length,
                   const unsigned char *fallback)
{
    if (!fail_open) {
        *slot = fallback;
    }
    if (wire != (const unsigned char *)0 && wire_length != 0u) {
        *slot = wire;
    }
}

static int read_item(int fail_open, const unsigned char *wire,
                     unsigned long wire_length)
{
    unsigned char local_cursor[1] = {0u};
    const unsigned char *cursor;
    choice_fn volatile apply_choice = choose;

    apply_choice(&cursor, fail_open, wire, wire_length, local_cursor);
    return (int)cursor[0];
}

int main(void)
{
    return read_item(1, (const unsigned char *)0, 0u);
}
