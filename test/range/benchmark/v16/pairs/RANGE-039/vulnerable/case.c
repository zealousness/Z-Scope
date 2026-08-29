typedef unsigned long size_t;

extern void *malloc(size_t size);
extern void free(void *pointer);
extern size_t strlen(const char *text);
extern int text_compare(const char *left, const char *right);
extern int text_prefix_compare(const char *left, const char *right, size_t count);
extern void *memcpy(void *destination, const void *source, size_t count);

typedef struct {
    int state;
} pthread_mutex_t;

static int pthread_mutex_init(pthread_mutex_t *mutex, const void *attributes)
{
    (void)attributes;
    mutex->state = 0;
    return 0;
}

static int guard_dispose(pthread_mutex_t *mutex)
{
    mutex->state = 0;
    return 0;
}

static int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    if (mutex->state != 0) {
        return 1;
    }
    mutex->state = 1;
    return 0;
}

static int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    if (mutex->state == 0) {
        return 1;
    }
    mutex->state = 0;
    return 0;
}

typedef struct ControlSession {
    const char *key;
    char *owner;
    pthread_mutex_t guard;
    struct ControlSession *next;
} ControlSession;

static ControlSession *g_control_sessions = (void *)0;
static pthread_mutex_t g_control_lock;

static void enter_guard(pthread_mutex_t *mutex)
{
    (void)pthread_mutex_lock(mutex);
}

static void leave_guard(pthread_mutex_t *mutex)
{
    (void)pthread_mutex_unlock(mutex);
}

static void release_memory(void *pointer)
{
    free(pointer);
}

static int process_message(const char *message)
{
    const char prefix[] = "REMOVE:";
    size_t prefix_length = strlen(prefix);
    ControlSession **cursor;
    ControlSession *session;

    if (text_prefix_compare(message, prefix, prefix_length) != 0) {
        return 0;
    }

    enter_guard(&g_control_lock);
    cursor = &g_control_sessions;
    while (*cursor != (void *)0 &&
           text_compare((*cursor)->key, message + prefix_length) != 0) {
        cursor = &(*cursor)->next;
    }
    session = *cursor;
    if (session != (void *)0) {
        *cursor = session->next;
    }
    leave_guard(&g_control_lock);

    if (session == (void *)0) {
        return 0;
    }

    return 1;
}

int main(void)
{
    const char key[] = "unit";
    const char owner[] = "holder";
    ControlSession *session;
    size_t owner_size;
    int result;

    if (pthread_mutex_init(&g_control_lock, (void *)0) != 0) {
        return 1;
    }

    session = (ControlSession *)malloc(sizeof(*session));
    if (session == (void *)0) {
        (void)guard_dispose(&g_control_lock);
        return 1;
    }

    owner_size = strlen(owner) + 1;
    session->owner = (char *)malloc(owner_size);
    if (session->owner == (void *)0) {
        release_memory(session);
        (void)guard_dispose(&g_control_lock);
        return 1;
    }

    (void)memcpy(session->owner, owner, owner_size);
    session->key = key;
    session->next = (void *)0;
    if (pthread_mutex_init(&session->guard, (void *)0) != 0) {
        release_memory(session->owner);
        release_memory(session);
        (void)guard_dispose(&g_control_lock);
        return 1;
    }

    g_control_sessions = session;
    result = process_message("REMOVE:unit");
    (void)guard_dispose(&g_control_lock);
    return result == 1 ? 0 : 1;
}
