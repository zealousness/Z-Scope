struct local_state {
    int item_count;
    int busy_flag;
    int ready_flag;
};

static struct local_state state;
static int stub_result = 8;

static int read_stub(void)
{
    return stub_result;
}

static int poll_once(void)
{
    int count = read_stub();

    if (count < 0) {
        count = 0;
    }
    state.item_count = count;
    state.busy_flag = count > 0;
    return state.busy_flag;
}

static void apply_threshold(int count)
{
    if (count >= 8) {
        state.ready_flag = 1;
    }
}

static void initialize_state(void)
{
    state.item_count = 0;
    state.busy_flag = 0;
    state.ready_flag = 0;
    state.busy_flag = poll_once();
    apply_threshold(state.busy_flag);
}

int main(void)
{
    initialize_state();
    return 0;
}
