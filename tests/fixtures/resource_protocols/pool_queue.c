#include <stdio.h>
#include <stdlib.h>

typedef struct {
    unsigned generation;
    int value;
} Node;

typedef struct {
    Node slot;
    unsigned live;
    unsigned duplicate_returns;
} Pool;

typedef struct {
    Node *pending;
} Queue;

static Node *pool_take(Pool *pool) {
    if (pool->live) return NULL;
    pool->live = 1;
    pool->slot.generation++;
    return &pool->slot;
}

static void pool_give(Pool *pool, Node *node) {
    if (node != &pool->slot || !pool->live) {
        pool->duplicate_returns++;
        return;
    }
    pool->live = 0;
}

static int queue_send(Queue *queue, Node *node, int reject) {
    if (reject || queue->pending) return -1;
    queue->pending = node;
    return 0;
}

static void queue_complete(Queue *queue, Pool *pool) {
    Node *node = queue->pending;
    queue->pending = NULL;
    if (node) pool_give(pool, node);
}

static void submit_a(Pool *pool, Queue *queue, int reject) {
    Node *node = pool_take(pool);
    if (!node) return;
    queue_send(queue, node, reject);
    pool_give(pool, node);
}

static void submit_b(Pool *pool, Queue *queue, int reject) {
    Node *node = pool_take(pool);
    if (!node) return;
    if (queue_send(queue, node, reject) != 0) pool_give(pool, node);
}

static void submit_c(Pool *pool, Queue *queue, int reject) {
    Node *node = pool_take(pool);
    if (!node) return;
    if (queue_send(queue, node, reject) != 0) return;
}

static void cancel_a(Queue *queue, Pool *pool) {
    if (queue->pending) pool_give(pool, queue->pending);
}

static void cancel_b(Queue *queue, Pool *pool) {
    Node *node = queue->pending;
    queue->pending = NULL;
    if (node) pool_give(pool, node);
}

int main(int argc, char **argv) {
    Pool pool = {0};
    Queue queue = {0};
    if (argc != 2) return 2;
    switch (atoi(argv[1])) {
        case 0: submit_a(&pool, &queue, 0); break;
        case 1: submit_b(&pool, &queue, 0); break;
        case 2: submit_c(&pool, &queue, 1); break;
        case 3: submit_b(&pool, &queue, 1); break;
        case 4: submit_b(&pool, &queue, 0); cancel_a(&queue, &pool); break;
        case 5: submit_b(&pool, &queue, 0); cancel_b(&queue, &pool); break;
        default: return 2;
    }
    queue_complete(&queue, &pool);
    printf("{\"live\":%u,\"duplicate_returns\":%u}\n",
           pool.live, pool.duplicate_returns);
    return 0;
}
