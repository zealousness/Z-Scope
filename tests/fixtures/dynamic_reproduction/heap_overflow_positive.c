/* V01 dynamic-reproduction positive fixture.
 *
 * Deliberately vulnerable: the loop writes `length` bytes into a 16-byte heap
 * buffer. Only the controlled ASAN runner may execute this file.
 */

#include <stdlib.h>

int zscope_dynamic_repro_positive(int length)
{
    char *buffer = (char *)malloc(16);
    int index;
    int total = 0;

    if (buffer == NULL) {
        return -1;
    }
    for (index = 0; index < length; index++) {
        buffer[index] = (char)(index & 0x7f); /* ZSCOPE_CANDIDATE_SITE */
        total += (int)buffer[index];
    }
    free(buffer);
    return total;
}

int main(int argc, char **argv)
{
    int length = argc > 1 ? atoi(argv[1]) : 64;
    int total = zscope_dynamic_repro_positive(length);
    return total < 0 ? 1 : 0;
}
