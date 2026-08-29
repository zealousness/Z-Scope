struct gate {
    unsigned held;
};

static struct gate shared_gate = {0U};
static char item;

static void acquire(struct gate *value)
{
    value->held += 1U;
}

static void release(struct gate *value)
{
    value->held -= 1U;
}

static char *make_item(int fail)
{
    if (fail) {
        return (char *)0;
    }
    return &item;
}

static int refresh(int fail)
{
    char *next;

    acquire(&shared_gate);
    next = make_item(fail);
    if (!next) {
        return -1;
    }
    release(&shared_gate);
    return 0;
}

int main(void)
{
    (void)refresh(1);
    return shared_gate.held == 0U ? 0 : 1;
}
