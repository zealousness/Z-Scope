/* V01 dynamic-reproduction wrong-object fixture.
 *
 * The candidate points at the safe store inside zscope_dynamic_repro_candidate.
 * The program then overflows an unrelated heap buffer inside a different
 * function. A sanitizer report therefore exists, but it belongs to another
 * object and site, and must never confirm the candidate.
 */

#include <stdlib.h>

int zscope_dynamic_repro_candidate(int value)
{
    char *owned = (char *)malloc(16);
    int total = 0;

    if (owned == NULL) {
        return -1;
    }
    owned[0] = (char)(value & 0x7f); /* ZSCOPE_CANDIDATE_SITE */
    total += (int)owned[0];
    free(owned);
    return total;
}

static int unrelated_helper(int length)
{
    char *other = (char *)malloc(8);
    int index;
    int total = 0;

    if (other == NULL) {
        return -1;
    }
    for (index = 0; index < length; index++) {
        other[index] = (char)(index & 0x7f); /* ZSCOPE_UNRELATED_SITE */
        total += (int)other[index];
    }
    free(other);
    return total;
}

int main(int argc, char **argv)
{
    int length = argc > 1 ? atoi(argv[1]) : 64;
    int total = zscope_dynamic_repro_candidate(length);
    total += unrelated_helper(length);
    return total < 0 ? 1 : 0;
}
