typedef unsigned long size_type;

void *memcpy(void *restrict destination,
             const void *restrict source,
             size_type count);

typedef struct {
    unsigned int tag;
    unsigned int length;
} FrameHeader;

static const unsigned int expected_tag = 0x13579bdfu;

int decode_window(const unsigned char *wire, size_type wire_len,
                  unsigned char *out, size_type out_len)
{
    FrameHeader header;
    size_type body_len;

    if (wire_len < sizeof header) {
        return 0;
    }

    memcpy(&header, wire, sizeof header);
    if (header.tag != expected_tag) {
        return 0;
    }

    if ((size_type)header.length < sizeof header ||
        (size_type)header.length > wire_len) {
        return 0;
    }

    body_len = (size_type)header.length - sizeof header;
    if (body_len > out_len) {
        return 0;
    }

    memcpy(out, wire + sizeof header, body_len);
    return 1;
}

int main(void)
{
    return 0;
}
