/* V02 dynamic-reproduction ThreadSanitizer negative fixture.
 *
 * The same shared counter is updated under a mutex, so every conflicting
 * access is ordered: no data race may be reported.
 */

#include <pthread.h>
#include <stdlib.h>

static int shared_counter = 0;
static pthread_mutex_t shared_lock = PTHREAD_MUTEX_INITIALIZER;

static void *zscope_race_writer(void *argument)
{
    int index;
    (void)argument;
    for (index = 0; index < 100000; index++) {
        if (pthread_mutex_lock(&shared_lock) != 0) {
            return NULL;
        }
        shared_counter = shared_counter + 1; /* ZSCOPE_SAFE_SITE */
        pthread_mutex_unlock(&shared_lock);
    }
    return NULL;
}

int main(void)
{
    pthread_t first;
    pthread_t second;

    if (pthread_create(&first, NULL, zscope_race_writer, NULL) != 0) {
        return 1;
    }
    if (pthread_create(&second, NULL, zscope_race_writer, NULL) != 0) {
        return 1;
    }
    if (pthread_join(first, NULL) != 0) {
        return 1;
    }
    if (pthread_join(second, NULL) != 0) {
        return 1;
    }
    return shared_counter > 0 ? 0 : 1;
}
