typedef unsigned char byte_type;
typedef unsigned long size_type;

enum operation_mode {
    mode_rpc = 1
};

struct task_record {
    unsigned int failed;
    unsigned int selected;
    unsigned int descriptor_ready;
    unsigned int object_visible;
    unsigned int session_visible;
};

static unsigned int bridge_events;
static unsigned int exposure_events;
static unsigned int publication_events;

static void adapt_descriptor(struct task_record *task);
static void expose_record(struct task_record *task);
static void publish_record(struct task_record *task);

static void adapt_descriptor(struct task_record *task)
{
    task->descriptor_ready = 1U;
    bridge_events += 1U;
}

static void expose_record(struct task_record *task)
{
    task->object_visible = 1U;
    exposure_events += 1U;
}

static void publish_record(struct task_record *task)
{
    task->session_visible = 1U;
    publication_events += 1U;
}

static int choose_value(struct task_record *task,
                        const byte_type *report,
                        size_type report_size)
{
    unsigned int reported;

    if (report_size == 0UL) {
        return -1;
    }

    reported = (unsigned int)report[0];
    if (reported == 0U) {
        return -1;
    }

    if (task->failed != 0U) {
        return -1;
    }

    task->selected = 1U;
    return 0;
}

static int route_message(struct task_record *task,
                         unsigned int mode,
                         const byte_type *report,
                         size_type report_size)
{
    if (mode == (unsigned int)mode_rpc) {
        if (choose_value(task, report, report_size) != 0) {
            return -1;
        }
        adapt_descriptor(task);
        expose_record(task);
        publish_record(task);
    }

    return 0;
}

int main(void)
{
    struct task_record task = {0U, 0U, 0U, 0U, 0U};
    const byte_type report[1] = {0U};

    (void)route_message(&task, (unsigned int)mode_rpc, report, 1UL);
    return 0;
}
