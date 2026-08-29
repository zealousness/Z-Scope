typedef struct Node Node;

struct Node {
    char *value;
    int state;
    Node *next;
};

typedef struct {
    Node *head;
    int lock;
} Registry;

enum { STATE_ACTIVE = 1 };

static Registry registry;
static Node node_pool;
static int node_pool_used;
static char value_pool[16];
static int value_pool_used;
static int fail_value_copy;

Node *allocate_node(void)
{
    if (node_pool_used != 0) {
        return (Node *)0;
    }
    node_pool_used = 1;
    node_pool.value = (char *)0;
    node_pool.state = 0;
    node_pool.next = (Node *)0;
    return &node_pool;
}

void recycle_node(Node *node)
{
    if (node == &node_pool) {
        node_pool_used = 0;
    }
}

char *copy_value(const char *source)
{
    unsigned long length = 0;
    unsigned long index;

    if (fail_value_copy != 0 || value_pool_used != 0) {
        return (char *)0;
    }
    while (source[length] != '\0') {
        if (length + 1UL >= sizeof value_pool) {
            return (char *)0;
        }
        length++;
    }
    for (index = 0; index <= length; index++) {
        value_pool[index] = source[index];
    }
    value_pool_used = 1;
    return value_pool;
}

void enter_lock(int *lock)
{
    *lock = 1;
}

void leave_lock(int *lock)
{
    *lock = 0;
}

void add_value(const char *value)
{
    Node *node = allocate_node();

    if (node == (Node *)0) {
        return;
    }
    node->value = copy_value(value);
    if (node->value == (char *)0) {
        recycle_node(node);
        return;
    }
    node->state = STATE_ACTIVE;

    enter_lock(&registry.lock);
    node->next = registry.head;
    registry.head = node;
    leave_lock(&registry.lock);
}

int main(void)
{
    fail_value_copy = 1;
    add_value("x");
    return registry.head == (Node *)0 && node_pool_used == 0 ? 0 : 1;
}
