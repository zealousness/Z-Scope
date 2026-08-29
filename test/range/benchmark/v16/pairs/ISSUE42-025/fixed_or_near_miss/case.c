enum state_code {
    STATE_PENDING = 0,
    STATE_NORMAL = 1
};

typedef struct {
    int identity;
    int state;
} record;

static record table[1];

static unsigned int select_entry(void)
{
    return 0u;
}

static int read_identity(void)
{
    return 0;
}

static void publish_entry(unsigned int index, int identity)
{
    if (identity == 0) {
        table[index].identity = identity;
        table[index].state = STATE_NORMAL;
        return;
    }

    table[index].identity = identity;
    table[index].state = STATE_NORMAL;
}

static int require_normal(unsigned int index)
{
    return table[index].state == STATE_NORMAL ? 0 : -1;
}

int main(void)
{
    unsigned int index = select_entry();
    int identity = read_identity();

    table[index].state = STATE_PENDING;
    publish_entry(index, identity);
    return require_normal(index);
}
