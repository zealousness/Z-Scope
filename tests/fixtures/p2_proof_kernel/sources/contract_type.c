#include <stdint.h>

struct neutral_packet {
    uint32_t length;
    uint8_t *data;
};

uint32_t neutral_contract_type(const struct neutral_packet *packet) {
    return packet->length;
}
