typedef __SIZE_TYPE__ size_t;

int receive_chunk(int fd, unsigned char *buf, size_t len);

int receive_chunk(int fd, unsigned char *buf, size_t len)
{
    (void)fd;
    (void)buf;
    (void)len;
    return 0;
}

int read_header(int fd)
{
    unsigned char header[4];
    size_t received = 0;

    while (received < sizeof header) {
        int rc = receive_chunk(fd, header + received,
                               sizeof header - received);
        if (rc <= 0) {
            return -1;
        }
        received += (size_t)rc;
    }
    return 0;
}

int main(void)
{
    return 0;
}
