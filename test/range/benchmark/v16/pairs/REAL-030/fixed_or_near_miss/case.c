enum { KEY_LIMIT = 31 };

typedef struct ServiceNode {
    char key[KEY_LIMIT + 1];
    int value;
} ServiceNode;

static ServiceNode stored_node;
static ServiceNode *root;
static int used;

static unsigned long text_length(const char *text)
{
    unsigned long count = 0U;
    while (text[count] != '\0') {
        ++count;
    }
    return count;
}

static int text_equal(const char *left, const char *right)
{
    unsigned long index = 0U;
    while (left[index] == right[index]) {
        if (left[index] == '\0') {
            return 1;
        }
        ++index;
    }
    return 0;
}

static void copy_key(char target[KEY_LIMIT + 1], const char *source)
{
    unsigned long count = text_length(source);
    unsigned long index = 0U;
    if (count > (unsigned long)KEY_LIMIT) {
        count = (unsigned long)KEY_LIMIT;
    }
    while (index < count) {
        target[index] = source[index];
        ++index;
    }
    target[count] = '\0';
}

static ServiceNode *find_node(const char *key)
{
    if (root != (ServiceNode *)0 && text_equal(root->key, key) != 0) {
        return root;
    }
    return (ServiceNode *)0;
}

static ServiceNode *allocate_node(void)
{
    if (used != 0) {
        return (ServiceNode *)0;
    }
    used = 1;
    return &stored_node;
}

static int insert_node(ServiceNode *node)
{
    root = node;
    return 0;
}

int select_value(const char *route_key, int policy_id)
{
    ServiceNode *node;
    if (text_length(route_key) > (unsigned long)KEY_LIMIT) {
        return -1;
    }
    node = find_node(route_key);
    if (node != (ServiceNode *)0) {
        return node->value;
    }
    node = allocate_node();
    if (node == (ServiceNode *)0) {
        return -1;
    }
    copy_key(node->key, route_key);
    node->value = policy_id;
    return insert_node(node);
}

int main(void)
{
    (void)select_value("01234567890123456789012345678901", 1);
    return 0;
}
