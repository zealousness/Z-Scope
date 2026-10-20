/* V02 dynamic-reproduction ThreadSanitizer positive fixture.
 *
 * Two threads increment one shared global without synchronization, so the
 * marked update is an unsynchronized conflicting access.
 */

#include <pthread.h>
#include <stdlib.h>

static int shared_counter = 0;

static void *zscope_race_writer(void *argument)
{
    int index;
    (void)argument;
    for (index = 0; index < 100000; index++) {
        shared_counter = shared_counter + 1; /* ZSCOPE_CANDIDATE_SITE */
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
