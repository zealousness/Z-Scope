struct item {
    int marker;
};

static struct item primary;
static int active_count;
static _Thread_local int owner_slot[2];

static void begin(int identity)
{
    active_count += 1;
    owner_slot[identity - 1] = identity;
}

static int mismatch(int identity)
{
    return owner_slot[identity - 1] != identity;
}

static void finish(int identity)
{
    owner_slot[identity - 1] = 0;
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
