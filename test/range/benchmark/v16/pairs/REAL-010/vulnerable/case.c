typedef unsigned int uint32_t;
typedef unsigned long size_t;

_Static_assert(sizeof(uint32_t) == 4, "four-byte type required");

uint32_t decode_word(const unsigned char *packet, size_t len)
{
    if (packet == (const unsigned char *)0 || len < 2) {
        return 0;
    }

    return *(const uint32_t *)(packet + 1);
}

int main(void)
{
    _Alignas(uint32_t) const unsigned char packet[5] = {0, 1, 0, 0, 0};
    return decode_word(packet, 2) == 0 ? 0 : 1;
}
