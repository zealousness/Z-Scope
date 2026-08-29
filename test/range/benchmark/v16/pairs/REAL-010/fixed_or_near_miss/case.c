typedef unsigned int uint32_t;
typedef unsigned long size_t;

_Static_assert(sizeof(uint32_t) == 4, "four-byte type required");

void *memcpy(void *restrict destination, const void *restrict source, size_t count);

uint32_t decode_word(const unsigned char *packet, size_t len)
{
    uint32_t value = 0;

    if (packet == (const unsigned char *)0 ||
        len < 1 + sizeof(uint32_t)) {
        return 0;
    }

    memcpy(&value, packet + 1, sizeof(value));
    return value;
}

int main(void)
{
    _Alignas(uint32_t) const unsigned char packet[5] = {0, 1, 0, 0, 0};
    return decode_word(packet, 2) == 0 ? 0 : 1;
}
