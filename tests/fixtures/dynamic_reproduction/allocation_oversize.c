/* V01 dynamic-reproduction resource-exhaustion fixture.
 *
 * Allocates exactly what the caller asks for, so an oversized argument becomes
 * a real sanitizer allocation-limit report. A memory-limit outcome must stay
 * undecided and must never be treated as a safety refutation.
 */

#include <stdlib.h>

void *zscope_dynamic_repro_allocate(unsigned long long size)
{
    void *block = malloc((size_t)size); /* ZSCOPE_CANDIDATE_SITE */

    if (block == NULL) {
        return NULL;
    }
    ((char *)block)[0] = 1;
    return block;
}

int main(int argc, char **argv)
{
    unsigned long long size = 1024;
    void *block;

    if (argc > 1) {
        size = strtoull(argv[1], NULL, 10);
    }
    block = zscope_dynamic_repro_allocate(size);
    free(block);
    return 0;
}
