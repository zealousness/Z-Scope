#include "wiki_demo_api.h"

#include <string.h>

int wiki_decode_frame(const uint8_t *frame, size_t frame_len,
                      uint8_t *out, size_t out_len) {
    if (frame == NULL || out == NULL || frame_len > out_len) {
        return -1;
    }

    memcpy(out, frame, frame_len);
    return (int)frame_len;
}
