typedef unsigned int word32;
typedef __SIZE_TYPE__ size_type;

_Static_assert(sizeof(word32) == 4, "word size");
_Static_assert(_Alignof(word32) > 1, "word alignment");

word32 read_value(const unsigned char *packet, size_type len)
{
    if (packet == 0 || len < 5U) {
        return 0U;
    }
    return *(const word32 *)(packet + 1);
}

int main(void)
{
    _Alignas(word32) unsigned char packet[5] = {0U, 1U, 2U, 3U, 4U};
    return (int)(read_value(packet, sizeof packet) & 1U);
}
