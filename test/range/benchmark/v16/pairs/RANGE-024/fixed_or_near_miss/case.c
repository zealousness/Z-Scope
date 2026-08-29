typedef void (*task_fn)(void *);

void *malloc(unsigned long);
void free(void *);

struct parcel {
    int value;
};

static task_fn pending_action;
static void *pending_context;
static volatile int observed;

static int defer(task_fn action, void *context)
{
    if (pending_action != 0) {
        return 2;
    }
    pending_action = action;
    pending_context = context;
    return 0;
}

static void execute_deferred(void)
{
    task_fn action = pending_action;
    void *context = pending_context;

    pending_action = 0;
    pending_context = (void *)0;
    if (action != 0) {
        action(context);
    }
}

static void consume(void *context)
{
    struct parcel *item = context;

    observed = item->value;
    free(item);
}

static int prepare(void)
{
    struct parcel *item;
    int status;

    item = malloc(sizeof(*item));
    if (item == (void *)0) {
        return 1;
    }
    item->value = 17;
    status = defer(consume, item);
    if (status != 0) {
        free(item);
        return status;
    }
    return 0;
}

int main(void)
{
    int status = prepare();

    if (status != 0) {
        return status;
    }
    execute_deferred();
    return observed == 17 ? 0 : 1;
}
