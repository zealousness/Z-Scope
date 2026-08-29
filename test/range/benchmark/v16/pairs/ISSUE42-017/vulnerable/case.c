enum {
    STATE_RUNNING = 1,
    STATE_COMPLETED = 2,
    SLOT_LIMIT = 2,
    TEXT_LIMIT = 16
};

typedef struct {
    volatile int state;
    int owner;
    char tag[TEXT_LIMIT];
} Slot;

typedef struct {
    volatile int held;
} Guard;

static Slot slots[SLOT_LIMIT];
static Guard slots_guard;
static void (*interleave_hook)(int);

static void guard_enter(Guard *guard)
{
    while (__sync_lock_test_and_set(&guard->held, 1) != 0) {
    }
}

static void guard_leave(Guard *guard)
{
    __sync_lock_release(&guard->held);
}

static int state_change(volatile int *location, int before, int after)
{
    return __sync_val_compare_and_swap(location, before, after) == before;
}

static void text_copy(char *destination, const char *source, int capacity)
{
    int index = 0;

    while (index + 1 < capacity && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

static void competing_claim(int index)
{
    (void)state_change(
        &slots[index].state, STATE_COMPLETED, STATE_RUNNING);
}

int claim_slot(const char *tag, int owner)
{
    int index = SLOT_LIMIT;
    int cursor;

    guard_enter(&slots_guard);
    for (cursor = 0; cursor < SLOT_LIMIT; ++cursor) {
        if (slots[cursor].state == STATE_COMPLETED) {
            index = cursor;
            break;
        }
    }
    guard_leave(&slots_guard);

    if (index == SLOT_LIMIT) {
        return SLOT_LIMIT;
    }

    if (interleave_hook != 0) {
        interleave_hook(index);
    }

    (void)state_change(
        &slots[index].state, STATE_COMPLETED, STATE_RUNNING);
    slots[index].owner = owner;
    text_copy(slots[index].tag, tag, TEXT_LIMIT);
    return index;
}

int main(void)
{
    int result;

    slots[0].state = STATE_COMPLETED;
    slots[0].owner = 7;
    text_copy(slots[0].tag, "old", TEXT_LIMIT);
    slots[1].state = STATE_RUNNING;
    interleave_hook = competing_claim;

    result = claim_slot("new", 9);
    return result == 0 && slots[0].owner == 9 && slots[0].tag[0] == 'n'
        ? 0
        : 1;
}
