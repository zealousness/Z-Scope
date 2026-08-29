typedef struct {
    int held;
} pthread_mutex_t;

typedef struct {
    pthread_mutex_t ctrl_lock;
} PipeNode;

typedef struct {
    pthread_mutex_t sched_lock;
    PipeNode *active;
} Scheduler;

static PipeNode node = {{0}};
static Scheduler g_pipe_scheduler = {{0}, &node};

static void acquire_gate(pthread_mutex_t *mutex)
{
    mutex->held = 1;
}

static void release_gate(pthread_mutex_t *mutex)
{
    mutex->held = 0;
}

static void observe(const char *message)
{
    (void)message;
}

static void dispatch_path(PipeNode *target)
{
    acquire_gate(&g_pipe_scheduler.sched_lock);
    acquire_gate(&target->ctrl_lock);
    observe("dispatch");
    release_gate(&target->ctrl_lock);
    release_gate(&g_pipe_scheduler.sched_lock);
}

static void close_path(void)
{
    PipeNode *target;

    target = g_pipe_scheduler.active;
    acquire_gate(&target->ctrl_lock);
    acquire_gate(&g_pipe_scheduler.sched_lock);
    observe("close");
    release_gate(&g_pipe_scheduler.sched_lock);
    release_gate(&target->ctrl_lock);
}

int main(void)
{
    dispatch_path(&node);
    close_path();
    return 0;
}
