typedef struct {
    unsigned int magic;
    unsigned int segment_count;
} Header;

typedef struct {
    unsigned int value;
} Segment;

enum {
    STREAM_MAGIC = 0x5354524du,
    SEGMENT_LIMIT = 8u
};

static Header default_header(void)
{
    Header value = { STREAM_MAGIC, 0u };
    return value;
}

static Header parse_header(Header wire)
{
    if (wire.magic == STREAM_MAGIC) {
        return wire;
    }
    return default_header();
}

unsigned int compact_segments(Header wire)
{
    Header header = parse_header(wire);
    Segment segments[SEGMENT_LIMIT] = { { 0u } };
    unsigned int i = 0u;
    unsigned int j;
    unsigned int total = 0u;

    while (i < header.segment_count && i < SEGMENT_LIMIT) {
        segments[i].value = i + 1u;
        ++i;
    }

    for (j = 0u; j < SEGMENT_LIMIT; ++j) {
        total += segments[j].value;
    }
    return total;
}

int main(void)
{
    Header below = { STREAM_MAGIC, 7u };
    Header at = { STREAM_MAGIC, 8u };
    Header above = { STREAM_MAGIC, 9u };
    unsigned int result = compact_segments(below);

    result ^= compact_segments(at);
    result ^= compact_segments(above);
    return (int)(result & 1u);
}
