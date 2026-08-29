typedef unsigned int unit;

_Static_assert(sizeof(unit) == 4, "unit must be 32 bits");

static void *reserve(unit count, unsigned long width)
{
    static unit slot;
    (void)count;
    (void)width;
    return &slot;
}

static int inspect(unit area)
{
    unit *items = reserve(area + 1U, (unsigned long)sizeof(*items));
    if (items != 0) {
        items[0] = 0U;
    }
    return 0;
}

static int invoke(const char *label, int mode, unit *count)
{
    (void)label;
    *count = (unit)(mode + 1);
    return inspect(*count);
}

int main(void)
{
    unit count = 0U;
    (void)invoke("local-service", -2, &count);
    return 0;
}
