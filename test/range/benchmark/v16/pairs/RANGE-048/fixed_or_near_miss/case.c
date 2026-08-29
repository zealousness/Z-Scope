typedef struct {
    unsigned int state;
} lock_type;

static unsigned int shared_value;
static lock_type shared_lock;

static void enter_lock(lock_type *lock)
{
    while (__atomic_exchange_n(&lock->state, 1U, __ATOMIC_ACQUIRE) != 0U) {
    }
}

static void leave_lock(lock_type *lock)
{
    __atomic_store_n(&lock->state, 0U, __ATOMIC_RELEASE);
}

static unsigned int update_value(unsigned int addend)
{
    unsigned int result;

    enter_lock(&shared_lock);
    result = shared_value + addend;
    shared_value = result;
    leave_lock(&shared_lock);

    return result;
}

int main(void)
{
    return update_value(1U) == 1U ? 0 : 1;
}
