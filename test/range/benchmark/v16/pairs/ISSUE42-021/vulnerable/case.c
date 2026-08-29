typedef struct Node Node;

struct Node {
    char name[16];
    Node *next;
};

typedef struct {
    _Atomic unsigned int next_ticket;
    _Atomic unsigned int serving_ticket;
} Lock;

static Node pool[2];
static _Atomic unsigned int used;
static _Atomic(Node *) head;
static Lock list_lock;
static _Thread_local int local_errno;

enum { ERR_EXISTS = 17, ERR_NO_MEMORY = 12 };

static void lock_enter(Lock *lock)
{
    unsigned int ticket = lock->next_ticket++;

    while (lock->serving_ticket != ticket) {
    }
}

static void lock_leave(Lock *lock)
{
    lock->serving_ticket++;
}

static void string_copy(char *destination, const char *source,
                        unsigned int capacity)
{
    unsigned int index = 0U;

    while (index + 1U < capacity && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

static Node *allocate_node(void)
{
    unsigned int index = used++;

    if (index >= 2U) {
        return (Node *)0;
    }
    return &pool[index];
}

static Node *find_node(const char *name)
{
    Node *cursor = head;

    while (cursor != (Node *)0) {
        unsigned int index = 0U;

        while (cursor->name[index] == name[index] &&
               name[index] != '\0') {
            ++index;
        }
        if (cursor->name[index] == name[index]) {
            return cursor;
        }
        cursor = cursor->next;
    }
    return (Node *)0;
}

static Node *create_named_node(const char *name)
{
    Node *node;

    if (find_node(name) != (Node *)0) {
        local_errno = ERR_EXISTS;
        return (Node *)0;
    }

    node = allocate_node();
    if (node == (Node *)0) {
        local_errno = ERR_NO_MEMORY;
        return (Node *)0;
    }
    string_copy(node->name, name, 16U);

    lock_enter(&list_lock);
    node->next = head;
    head = node;
    lock_leave(&list_lock);
    return node;
}

int main(void)
{
    Node *first = create_named_node("item");
    Node *second = create_named_node("item");

    if (first == (Node *)0 || second != (Node *)0 ||
        local_errno != ERR_EXISTS) {
        return 1;
    }
    return 0;
}
