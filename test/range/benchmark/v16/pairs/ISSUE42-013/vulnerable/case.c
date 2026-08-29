typedef void (*Action)(void);

typedef struct {
    Action first;
    Action second;
} Entry;

typedef struct {
    int held;
} Gate;

enum { SLOT_COUNT = 4 };

static Entry *slots[SLOT_COUNT];
static Gate gate;

static void acquire(Gate *value)
{
    value->held = 1;
}

static void release(Gate *value)
{
    value->held = 0;
}

static int register_entry(int type, Entry *candidate)
{
    if (type < 0 || type >= SLOT_COUNT) {
        return -1;
    }

    if (slots[type] != 0) {
        acquire(&gate);
        slots[type]->first = candidate->first;
        slots[type]->second = candidate->second;
        release(&gate);
        return 1;
    }

    acquire(&gate);
    slots[type] = candidate;
    release(&gate);
    return 0;
}

static void action(void)
{
}

int main(void)
{
    Entry entry = { action, action };
    return register_entry(0, &entry);
}
