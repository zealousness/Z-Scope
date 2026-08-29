enum { KEY_LIMIT = 128, NODE_CAPACITY = 4 };

typedef struct Node Node;
struct Node {
    char key[KEY_LIMIT];
    int value;
    Node *left;
    Node *right;
};

static Node pool[NODE_CAPACITY];
static unsigned pool_used;
static Node *tree_root;

static unsigned text_length(const char *text)
{
    unsigned length = 0u;
    while (text[length] != '\0') {
        length++;
    }
    return length;
}

static int compare_text(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        left++;
        right++;
    }
    if ((unsigned char)*left < (unsigned char)*right) {
        return -1;
    }
    return (unsigned char)*left > (unsigned char)*right;
}

static void copy_text(char destination[KEY_LIMIT], const char *source)
{
    unsigned length = text_length(source);
    unsigned index = 0u;
    if (length >= (unsigned)KEY_LIMIT) {
        length = (unsigned)KEY_LIMIT - 1u;
    }
    while (index < length) {
        destination[index] = source[index];
        index++;
    }
    destination[length] = '\0';
}

static void *allocate_zeroed(unsigned count, unsigned size)
{
    Node *node;
    unsigned index = 0u;
    if (count != 1u || size != (unsigned)sizeof(Node) ||
        pool_used >= (unsigned)NODE_CAPACITY) {
        return (void *)0;
    }
    node = &pool[pool_used++];
    while (index < (unsigned)KEY_LIMIT) {
        node->key[index++] = '\0';
    }
    node->value = 0;
    node->left = (Node *)0;
    node->right = (Node *)0;
    return node;
}

static Node *lookup(const char *key)
{
    Node *node = tree_root;
    while (node != (Node *)0) {
        int order = compare_text(key, node->key);
        if (order == 0) {
            return node;
        }
        node = order < 0 ? node->left : node->right;
    }
    return (Node *)0;
}

static void insert_node(const char *key, Node *fresh)
{
    Node *node;
    if (tree_root == (Node *)0) {
        tree_root = fresh;
        return;
    }
    node = tree_root;
    for (;;) {
        Node **next = compare_text(key, node->key) < 0
            ? &node->left : &node->right;
        if (*next == (Node *)0) {
            *next = fresh;
            return;
        }
        node = *next;
    }
}

int upsert(const char *key, int value)
{
    Node *node;
    if (key == (const char *)0) {
        return -1;
    }
    node = lookup(key);
    if (node != (Node *)0) {
        node->value = value;
        return 0;
    }
    node = allocate_zeroed(1u, (unsigned)sizeof(Node));
    if (node == (Node *)0) {
        return -1;
    }
    copy_text(node->key, key);
    node->value = value;
    insert_node(key, node);
    return 0;
}

int main(void)
{
    char key[KEY_LIMIT + 1];
    unsigned index = 0u;
    while (index < (unsigned)KEY_LIMIT) {
        key[index++] = 'x';
    }
    key[KEY_LIMIT] = '\0';
    (void)upsert(key, 1);
    (void)upsert(key, 2);
    return 0;
}
