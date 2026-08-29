void *malloc(unsigned long size);
void free(void *pointer);

struct ChildNode {
    char *name;
    struct ChildNode *next;
};

struct ParentNode {
    int key;
    struct ChildNode *children;
    struct ParentNode *next;
};

static int lock_state;

static void lock_acquire(void)
{
    lock_state = 1;
}

static void lock_release(void)
{
    lock_state = 0;
}

static void safe_release(void **slot)
{
    if (*slot != 0) {
        free(*slot);
        *slot = 0;
    }
}

static char *copy_text(const char *source)
{
    unsigned long length = 0;
    unsigned long index;
    char *copy;

    while (source[length] != '\0') {
        length++;
    }
    copy = malloc(length + 1UL);
    if (copy == 0) {
        return 0;
    }
    for (index = 0; index <= length; index++) {
        copy[index] = source[index];
    }
    return copy;
}

static struct ChildNode *create_child(const char *name)
{
    struct ChildNode *node = malloc(sizeof(*node));

    if (node == 0) {
        return 0;
    }
    node->name = copy_text(name);
    node->next = 0;
    if (node->name == 0) {
        void *owned = node;
        safe_release(&owned);
        return 0;
    }
    return node;
}

static struct ParentNode *create_parent(int key)
{
    struct ParentNode *node = malloc(sizeof(*node));

    if (node != 0) {
        node->key = key;
        node->children = 0;
        node->next = 0;
    }
    return node;
}

static void remove_parent(struct ParentNode **head, int key)
{
    struct ParentNode **cursor;

    lock_acquire();
    cursor = head;
    while (*cursor != 0 && (*cursor)->key != key) {
        cursor = &(*cursor)->next;
    }
    if (*cursor != 0) {
        struct ParentNode *node = *cursor;
        void *owned;

        *cursor = node->next;
        owned = node;
        safe_release(&owned);
    }
    lock_release();
}

int main(void)
{
    struct ParentNode *head = create_parent(1);
    struct ChildNode *first;
    struct ChildNode *second;

    if (head == 0) {
        return 0;
    }
    first = create_child("one");
    second = create_child("two");
    if (first != 0) {
        head->children = first;
        first->next = second;
    } else {
        head->children = second;
    }
    remove_parent(&head, 1);
    return 0;
}
