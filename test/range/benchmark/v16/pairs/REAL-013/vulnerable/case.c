typedef unsigned long size_t;
typedef unsigned int uint32_t;

void *memcpy(void *restrict destination,
             const void *restrict source,
             size_t count);

int copy_payload(const unsigned char *packet, size_t packet_len,
                 unsigned char *output, size_t output_len)
{
    uint32_t units;
    size_t copy_len;

    if (packet_len < 4u) {
        return -1;
    }

    units = packet[0];
    copy_len = (size_t)units * 8u;

    if (copy_len > output_len) {
        return -1;
    }

    memcpy(output, packet + 4u, copy_len);
    return 0;
}

int main(void)
{
    return 0;
}
