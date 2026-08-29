typedef struct {
    unsigned int state;
} lock_type;

static unsigned int shared_value;
static lock_type shared_lock;

static void enter_lock(lock_type *lock)
{
    (void)lock;
}

static void leave_lock(lock_type *lock)
{
    (void)lock;
}

static unsigned int update_value(unsigned int addend)
{
    unsigned int result;

    enter_lock(&shared_lock);
    result = shared_value + addend;
    shared_value = result;
    leave_lock(&shared_lock);

    return shared_value;
}

int main(void)
{
    return update_value(1U) == 1U ? 0 : 1;
}
