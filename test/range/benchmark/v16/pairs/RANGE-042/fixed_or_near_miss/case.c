typedef struct Node Node;

struct Node {
    int closed;
    Node *next;
};

static void park(Node **cursor)
{
    Node *node = *cursor;

    if (node != (Node *)0 && node->closed != 0) {
        *cursor = node->next;
        node->next = node;
    }
}

static int remains_reachable(Node *node)
{
    int steps = 3;

    while (node != (Node *)0 && steps > 0) {
        node = node->next;
        steps -= 1;
    }
    return node != (Node *)0;
}

int main(void)
{
    Node last = {0, (Node *)0};
    Node first = {1, &last};
    Node *head = &first;

    park(&head);
    return remains_reachable(head);
}
