enum { query_code = 1 };

struct record {
    int state;
};

static struct record registry = { 41 };

static int probe_command(int descriptor, int command)
{
    (void)descriptor;
    (void)command;
    return -1;
}

static int change_mode(int descriptor)
{
    int saved_state = registry.state;

    registry.state = descriptor;
    if (probe_command(descriptor, query_code) == -1) {
        registry.state = saved_state;
        return -1;
    }

    registry.state = saved_state;
    return 0;
}

int main(void)
{
    int entry_state = registry.state;
    int result = change_mode(9);

    return result == -1 && registry.state == entry_state ? 0 : 1;
}
