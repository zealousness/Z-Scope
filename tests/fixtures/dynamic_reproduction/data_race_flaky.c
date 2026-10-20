/* V02 dynamic-reproduction non-deterministic fixture.
 *
 * The reader only touches the shared slot when it observes a relaxed-atomic
 * gate, and the gate is armed after a wall-clock busy-wait. Observing the gate
 * creates no happens-before edge, so when the reader does reach the marked
 * store it races with the setter's store; when the reader's polling window
 * expires first the shared slot is never touched and no race is observable.
 *
 * Both outcomes are expected. The windows below were chosen from measurements
 * on the WSL acceptance machine (20 runs per configuration, clang 18.1.3,
 * ThreadSanitizer, -O0):
 *
 *   setter=500us  reader=500us   ->  5/20 reported
 *   setter=500us  reader=1000us  ->  7/20 reported   (chosen)
 *   setter=500us  reader=2000us  ->  5/20 reported
 *   setter=1000us reader=500us   ->  0/20 reported
 *   setter=2000us reader=1500us  ->  0/20 reported
 *
 * Because both windows are wall-clock based, a faster or slower machine changes
 * the ratio rather than fixing the outcome - which is exactly what the runner
 * must tolerate: a mixed replay is classified inconclusive and can never
 * confirm the candidate.
 */

#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#define ZSCOPE_SETTER_WINDOW_US 500
#define ZSCOPE_READER_WINDOW_US 1000

static atomic_int gate_flag = 0;
static int shared_slot = 0;
static volatile unsigned long idle_sink = 0;

static double zscope_now_ms(void)
{
    struct timespec stamp;

    clock_gettime(CLOCK_MONOTONIC, &stamp);
    return (double)stamp.tv_sec * 1000.0 + (double)stamp.tv_nsec / 1000000.0;
}

static void zscope_busy_wait_us(unsigned long window_us)
{
    double window_ms = (double)window_us / 1000.0;
    double start = zscope_now_ms();

    while (zscope_now_ms() - start < window_ms) {
        /* Unrelated to the shared slot: the pre-gate work cannot race. */
        idle_sink = idle_sink + 1;
    }
}

static void *zscope_flaky_setter(void *argument)
{
    (void)argument;
    zscope_busy_wait_us(ZSCOPE_SETTER_WINDOW_US);
    atomic_store_explicit(&gate_flag, 1, memory_order_relaxed);
    shared_slot = shared_slot + 1;
    return NULL;
}

static void *zscope_flaky_reader(void *argument)
{
    double window_ms = (double)ZSCOPE_READER_WINDOW_US / 1000.0;
    double start = zscope_now_ms();

    (void)argument;
    while (zscope_now_ms() - start < window_ms) {
        if (atomic_load_explicit(&gate_flag, memory_order_relaxed) == 1) {
            shared_slot = shared_slot + 2; /* ZSCOPE_CANDIDATE_SITE */
            return NULL;
        }
    }
    return NULL;
}

int main(void)
{
    pthread_t setter;
    pthread_t reader;

    if (pthread_create(&setter, NULL, zscope_flaky_setter, NULL) != 0) {
        return 1;
    }
    if (pthread_create(&reader, NULL, zscope_flaky_reader, NULL) != 0) {
        return 1;
    }
    if (pthread_join(setter, NULL) != 0) {
        return 1;
    }
    if (pthread_join(reader, NULL) != 0) {
        return 1;
    }
    return 0;
}
