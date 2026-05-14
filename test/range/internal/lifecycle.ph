#ifndef LIFECYCLE_PH
#define LIFECYCLE_PH

#include "../internal/types.ph"

int _lifecycle_service_init(uint32_t worker_count);
int _lifecycle_service_shutdown(void);

char* _lifecycle_parse_control_message(const char* msg);
int _lifecycle_add_entry(const char* key, const char* value);
const char* _lifecycle_get_value(const char* key);
int _lifecycle_remove_entry(const char* key);
int _lifecycle_ref_get(const char* key);
int _lifecycle_ref_put(const char* key);

int _lifecycle_register_entry_callback(const char* key, plugin_callback_t cb);
int _lifecycle_fire_registered_callback(void);
int _lifecycle_fire_callback_under_lock(void);
int _lifecycle_schedule_flush(const char* path);

int _lifecycle_reload_config(const char* text);
size_t _lifecycle_get_config_length(void);
int _lifecycle_wait_for_work(void);

int _lifecycle_resize_metrics(size_t count);
int _lifecycle_recv_packet(int fd, char* dst, size_t dst_size);
int _lifecycle_format_topic(const char* prefix, uint32_t id, char* out, size_t out_size);
int _lifecycle_send_status(int fd);
int _lifecycle_release_value_slice(char* line);
int _lifecycle_parse_frame(size_t field_count);
uint32_t _lifecycle_decode_unaligned_id(const unsigned char* packet, size_t len);

int _lifecycle_watch_connection(int fd);
int _lifecycle_close_connection(int fd);
int _lifecycle_dispatch_watched_event(char* buffer, size_t len);

int _lifecycle_map_rules(const char* path, size_t len);
int _lifecycle_unload_rules(void);
int _lifecycle_match_rule_byte(size_t offset);

#endif
