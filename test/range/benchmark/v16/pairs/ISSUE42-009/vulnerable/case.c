typedef struct {
    _Atomic unsigned int next_ticket;
    _Atomic unsigned int now_serving;
} RuntimeLock;

typedef struct RuntimeRcuBatch {
    int callback_id;
    struct RuntimeRcuBatch *next;
} RuntimeRcuBatch;

RuntimeLock g_runtime_rcu_lock;
_Atomic int g_runtime_rcu_next_pending;
RuntimeRcuBatch *g_runtime_rcu_batches;

static RuntimeRcuBatch pool[4];
static _Atomic unsigned int pool_next;

static void enter_gate(RuntimeLock *lock)
{
    unsigned int ticket = lock->next_ticket++;

    while (lock->now_serving != ticket) {
    }
}

static void leave_gate(RuntimeLock *lock)
{
    lock->now_serving++;
}

void *reserve_batch(unsigned long count, unsigned long size)
{
    unsigned int slot;

    if (count != 1UL || size != sizeof(RuntimeRcuBatch)) {
        return (void *)0;
    }

    slot = pool_next++;
    if (slot >= 4U) {
        return (void *)0;
    }

    return &pool[slot];
}

int submit_batch(int need_judge_pending, int callback_id)
{
    RuntimeRcuBatch *batch;

    if (need_judge_pending != 0 && g_runtime_rcu_next_pending != 0) {
        return 0;
    }

    batch = reserve_batch(1UL, sizeof(*batch));
    if (batch == (void *)0) {
        return -1;
    }

    batch->callback_id = callback_id;
    batch->next = (void *)0;

    enter_gate(&g_runtime_rcu_lock);
    g_runtime_rcu_next_pending = 1;
    batch->next = g_runtime_rcu_batches;
    g_runtime_rcu_batches = batch;
    leave_gate(&g_runtime_rcu_lock);

    return 1;
}

int main(void)
{
    int first = submit_batch(1, 1);
    int second = submit_batch(1, 2);

    return (first == 1 && second == 0) ? 0 : 1;
}
