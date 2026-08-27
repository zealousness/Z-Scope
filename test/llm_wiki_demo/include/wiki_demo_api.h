#ifndef WIKI_DEMO_API_H
#define WIKI_DEMO_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int wiki_copy_label(const char *label);
int wiki_execute_command(const char *command);
int wiki_decode_frame(const uint8_t *frame, size_t frame_len,
                      uint8_t *out, size_t out_len);
int wiki_parse_port(const char *text, uint16_t *port_out);
int wiki_register_callback(const char *name, void (*callback)(void));

#ifdef __cplusplus
}
#endif

#endif
