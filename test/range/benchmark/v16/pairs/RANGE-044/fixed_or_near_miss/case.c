typedef struct PipeNode {
    int pipe_id;
    int closed;
    struct PipeNode *next;
} PipeNode;

typedef struct Scheduler {
    PipeNode *head;
    int held;
} Scheduler;

static void acquire_guard(Scheduler *scheduler)
{
    scheduler->held = 1;
}

static void release_guard(Scheduler *scheduler)
{
    scheduler->held = 0;
}

static void record_value(int value)
{
    (void)value;
}

static int close_node(Scheduler *scheduler, int pipe_id)
{
    PipeNode **cursor;
    PipeNode *node;

    acquire_guard(scheduler);
    cursor = &scheduler->head;
    while (*cursor != 0 && (*cursor)->pipe_id != pipe_id) {
        cursor = &(*cursor)->next;
    }
    node = *cursor;
    if (node == 0) {
        release_guard(scheduler);
        return 0;
    }
    node->closed = 1;
    *cursor = node->next;
    node->next = node;
    record_value(node->pipe_id);
    release_guard(scheduler);
    return 1;
}

int main(void)
{
    PipeNode second = {2, 0, 0};
    PipeNode first = {1, 0, &second};
    Scheduler scheduler = {&first, 0};
    int first_result = close_node(&scheduler, 1);
    int second_result = close_node(&scheduler, 2);

    return first_result == 1 && second_result == 1 &&
           first.closed == 1 && second.closed == 1 &&
           scheduler.head == 0 && scheduler.held == 0 ? 0 : 1;
}
