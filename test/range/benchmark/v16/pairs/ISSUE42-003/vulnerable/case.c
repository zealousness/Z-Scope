typedef unsigned long span;

union byte_block
{
    unsigned char bytes[8];
    unsigned long long value;
};

static span first_changed_byte(const unsigned char *input, span len)
{
    union byte_block left;
    union byte_block right;
    unsigned long long difference;
    span i;

    if (input == 0 || len < 17) {
        return 0;
    }

    for (i = 0; i < 8; ++i) {
        left.bytes[i] = input[1 + i];
        right.bytes[i] = input[9 + i];
    }

    difference = left.value ^ right.value;
    if (difference == 0) {
        return 0;
    }

    for (i = 0; i < 8; ++i) {
        if ((difference & 255ULL) != 0) {
            return i;
        }
        difference >>= 8;
    }

    return 0;
}

int main(void)
{
    unsigned char data[17] = {0};

    if (first_changed_byte(data, sizeof data) != 0) {
        return 1;
    }

    data[1] = 1;
    if (first_changed_byte(data, sizeof data) != 0) {
        return 2;
    }

    data[1] = 0;
    data[4] = 1;
    if (first_changed_byte(data, sizeof data) != 3) {
        return 3;
    }

    data[4] = 0;
    data[8] = 1;
    if (first_changed_byte(data, sizeof data) != 7) {
        return 4;
    }

    return 0;
}
