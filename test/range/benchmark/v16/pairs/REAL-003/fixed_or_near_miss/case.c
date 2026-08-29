extern void free(void *);

struct item {
    void *payload;
};

int process_item(struct item *node, int mode)
{
    if (mode != 0) {
        free(node->payload);
        free(node);
        return -1;
    }

    return 0;
}

int main(void)
{
    return 0;
}
