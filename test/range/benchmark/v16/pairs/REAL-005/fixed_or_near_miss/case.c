void *malloc(unsigned long size);
void free(void *pointer);

typedef struct Node {
    char *name;
    void *payload;
} Node;

static void release_memory(void *pointer)
{
    if (pointer != 0) {
        free(pointer);
    }
}

static Node *allocate_node(void)
{
    Node *node = malloc(sizeof *node);

    if (node == 0) {
        return 0;
    }

    node->name = malloc(2UL);
    if (node->name == 0) {
        release_memory(node);
        return 0;
    }

    node->payload = malloc(sizeof(int));
    if (node->payload == 0) {
        release_memory(node->name);
        release_memory(node);
        return 0;
    }

    node->name[0] = 'x';
    node->name[1] = '\0';
    return node;
}

static int run(void)
{
    Node *node = allocate_node();

    if (node == 0) {
        return 1;
    }

    release_memory(node->payload);
    release_memory(node->name);
    release_memory(node);
    return 0;
}

int main(void)
{
    return run();
}
