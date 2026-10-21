/* V01 dynamic-reproduction negative fixture.
 *
 * The same shape as the positive case, correctly bounded: every write stays
 * inside the 16-byte heap buffer, so no sanitizer report may be produced.
 */

#include <stdlib.h>

int zscope_dynamic_repro_negative(int length)
{
    char *buffer = (char *)malloc(16);
    int index;
    int total = 0;
    int written = length > 16 ? 16 : length;

    if (buffer == NULL) {
        return -1;
    }
    for (index = 0; index < written; index++) {
        buffer[index] = (char)(index & 0x7f); /* ZSCOPE_SAFE_SITE */
        total += (int)buffer[index];
    }
    free(buffer);
    return total;
}

int main(int argc, char **argv)
{
    int length = argc > 1 ? atoi(argv[1]) : 64;
    int total = zscope_dynamic_repro_negative(length);
    return total < 0 ? 1 : 0;
}
