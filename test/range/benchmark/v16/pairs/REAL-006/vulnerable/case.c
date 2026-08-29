typedef struct Child Child;

struct Child {
    Child *next;
    int live;
};

typedef struct ServiceNode {
    Child *children;
    struct ServiceNode *next;
    int live;
} ServiceNode;

static ServiceNode node_store;
static Child child_store;
static ServiceNode *registry;
static int registry_locked;

static ServiceNode *allocate_node(void)
{
    node_store.children = 0;
    node_store.next = 0;
    node_store.live = 1;
    return &node_store;
}

static Child *allocate_child(void)
{
    child_store.next = 0;
    child_store.live = 1;
    return &child_store;
}

static void lock_registry(void)
{
    registry_locked = 1;
}

static void unlock_registry(void)
{
    registry_locked = 0;
}

static void insert_node(ServiceNode *node)
{
    if (registry_locked != 0) {
        node->next = registry;
        registry = node;
    }
}

static void remove_node(ServiceNode *node)
{
    ServiceNode **cursor = &registry;

    if (registry_locked == 0) {
        return;
    }
    while (*cursor != 0) {
        if (*cursor == node) {
            *cursor = node->next;
            node->next = 0;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

void release_children(Child *child)
{
    while (child != 0) {
        Child *next = child->next;
        child->live = 0;
        child = next;
    }
}

static void discard_node(ServiceNode *node)
{
    node->live = 0;
    node->children = 0;
    node->next = 0;
}

int activate_entry(const char *key, int activation_rc)
{
    ServiceNode *node;
    Child *child;

    if (key == 0) {
        return -1;
    }
    node = allocate_node();
    child = allocate_child();
    node->children = child;

    lock_registry();
    insert_node(node);
    unlock_registry();

    if (activation_rc != 0) {
        lock_registry();
        remove_node(node);
        unlock_registry();
        discard_node(node);
        return activation_rc;
    }
    return 0;
}

int main(void)
{
    int rc = activate_entry("x", 1);

    return rc == 1 && node_store.live == 0 && child_store.live == 0 ? 0 : 1;
}
