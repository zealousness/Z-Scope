typedef __SIZE_TYPE__ Size;

typedef union {
    long double alignment;
    unsigned char storage[64];
} pthread_mutex_t;

extern int mutex_prepare(pthread_mutex_t *mutex, const void *attributes);
extern int pthread_mutex_destroy(pthread_mutex_t *mutex);
extern int pthread_mutex_lock(pthread_mutex_t *mutex);
extern int pthread_mutex_unlock(pthread_mutex_t *mutex);
extern void *malloc(Size size);
extern void free(void *pointer);

typedef struct TopicSubscription {
    struct TopicSubscription *next;
    pthread_mutex_t mutex;
} TopicSubscription;

static TopicSubscription *subscription_head;
static pthread_mutex_t subscription_lock;

static void release_memory(void *pointer)
{
    free(pointer);
}

static int subscription_add(void)
{
    TopicSubscription *sub = malloc(sizeof(*sub));

    if (sub == (void *)0) {
        return 0;
    }
    sub->next = (void *)0;
    if (mutex_prepare(&sub->mutex, (const void *)0) != 0) {
        release_memory(sub);
        return 0;
    }
    (void)pthread_mutex_lock(&subscription_lock);
    sub->next = subscription_head;
    subscription_head = sub;
    (void)pthread_mutex_unlock(&subscription_lock);
    return 1;
}

static void subscription_remove(void)
{
    TopicSubscription *sub;

    (void)pthread_mutex_lock(&subscription_lock);
    sub = subscription_head;
    if (sub != (void *)0) {
        subscription_head = sub->next;
    }
    (void)pthread_mutex_unlock(&subscription_lock);
    if (sub != (void *)0) {
        (void)pthread_mutex_destroy(&sub->mutex);
        release_memory(sub);
    }
}

int main(void)
{
    if (mutex_prepare(&subscription_lock, (const void *)0) != 0) {
        return 1;
    }
    if (!subscription_add()) {
        (void)pthread_mutex_destroy(&subscription_lock);
        return 1;
    }
    subscription_remove();
    (void)pthread_mutex_destroy(&subscription_lock);
    return 0;
}
