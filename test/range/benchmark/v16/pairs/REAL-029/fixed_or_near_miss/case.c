static int watched_slot = -1;
static int descriptor_open = 1;

static void release_descriptor(int descriptor)
{
    (void)descriptor;
    descriptor_open = 0;
}

static int receive_data(int descriptor)
{
    return descriptor_open ? descriptor : -1;
}

static int handle_descriptor(int descriptor)
{
    int result;

    watched_slot = descriptor;
    result = receive_data(descriptor);
    watched_slot = -1;
    release_descriptor(descriptor);
    return result;
}

int main(void)
{
    int result = handle_descriptor(3);
    return (result == 3 && watched_slot == -1 && descriptor_open == 0) ? 0 : 1;
}
