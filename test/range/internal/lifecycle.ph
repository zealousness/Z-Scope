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

int _lifecycle_mesh_authorize_init(void);
int _lifecycle_mesh_control_message(const char* msg, int transport_id);
int _lifecycle_mesh_disconnect(const char* key);
int _lifecycle_customize_control_message(const char* msg, int protocol_id);
int _lifecycle_customize_transport_cleanup(int protocol_id);
int _lifecycle_register_guarded_subscription(const char* topic);
int _lifecycle_unregister_guarded_subscription(const char* topic);

int _lifecycle_scheduler_add_pipe(int pipe_id);
int _lifecycle_dispatch_pipe_tick(int expected_pipe_id);
int _lifecycle_close_pipe(int pipe_id);
int _lifecycle_tick_timer_callback(int pipe_id);

int _lifecycle_register_os_node(const char* os_name);
int _lifecycle_attach_proc_node(const char* os_name, int pid, const char* proc_name);
int _lifecycle_delete_os_node(const char* os_name);
int _lifecycle_avl_policy_upsert(const char* full_key, int policy_id);
int _lifecycle_avl_register_route(int key, int fail_after_insert);
int _lifecycle_avl_walk_duplicate_routes(int limit);
uint32_t _lifecycle_macro_guarded_counter_update(uint32_t delta);

#endif
