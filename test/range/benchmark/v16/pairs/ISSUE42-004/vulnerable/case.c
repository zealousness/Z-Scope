struct item {
    int marker;
    int owner;
};

static struct item primary;
static int active_count;

static void begin(int identity)
{
    active_count += 1;
    primary.owner = identity;
}

static int mismatch(int identity)
{
    return primary.owner != identity;
}

static void finish(int identity)
{
    (void)identity;
    primary.owner = 0;
    active_count -= 1;
}

int main(void)
{
    int observed = 0;

    begin(1);
    begin(2);
    observed += mismatch(1);
    finish(2);
    observed += mismatch(1);
    finish(1);

    return active_count != 0 || primary.marker != 0 || observed < 0;
}
