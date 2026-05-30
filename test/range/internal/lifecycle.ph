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
int _lifecycle_notify_entry_callback(void);
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
uint32_t _lifecycle_decode_packet_id(const unsigned char* packet, size_t len);

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
int _lifecycle_register_topic_subscription(const char* topic);
int _lifecycle_unregister_topic_subscription(const char* topic);

int _lifecycle_scheduler_add_pipe(int pipe_id);
int _lifecycle_dispatch_pipe_tick(int expected_pipe_id);
int _lifecycle_close_pipe(int pipe_id);
int _lifecycle_tick_timer_callback(int pipe_id);

int _lifecycle_register_os_node(const char* os_name);
int _lifecycle_attach_proc_node(const char* os_name, int pid, const char* proc_name);
int _lifecycle_delete_os_node(const char* os_name);
int _lifecycle_avl_policy_upsert(const char* route_key, int policy_id);
int _lifecycle_avl_register_route(int key, int route_flags);
int _lifecycle_avl_walk_duplicate_routes(int limit);
uint32_t _lifecycle_update_counter_slot(uint32_t delta);

int _runtime_remove_module_record(const char* key);
int _runtime_remove_system_node(const char* key);
int _runtime_apply_component_stage(const char* key, int stage_mode);
int _runtime_detach_component_record(const char* key, int config_remove_rc);
int _runtime_remove_file_record(const char* name);
int _runtime_activate_service_path(const char* key, int activation_rc);
int _runtime_release_reader_channel(const char* key, int role);
int _runtime_flush_log_buffer(const char* message, int emit_error);
int _runtime_publish_init_sequence(const char* key, const char* value);
uint32_t _runtime_message_header_probe(const unsigned char* packet, size_t len);
int _runtime_unload_patch_member(const char* key);
int _runtime_insert_policy_node(const char* key);
int _runtime_protocol_frame_length(const unsigned char* packet, size_t packet_len,
                                        unsigned char* out, size_t out_len);
uint64_t _runtime_read_control_magic(const unsigned char* blob, size_t len);
int _runtime_unload_resource_table(const char* key, int unload_now);
int _runtime_read_service_flag(const char* payload);
int _runtime_prune_patch_tree(const char* key);
int _runtime_query_peak_stats(uint32_t area, uint32_t* out_count);
int _runtime_read_peer_record(int fd, unsigned char* header, size_t header_len);
int _runtime_read_tls_record(int fd, int ssl_accept_times);
int _runtime_release_channel_role(const char* key, int role);
int _runtime_switch_io_mode(int fd);
int _runtime_link_allocated_node(const char* key);
int _runtime_release_shared_node(const char* key);
int _runtime_notify_registry_listener(const char* key, plugin_callback_t cb);
int _runtime_submit_background_work(const char* path);
int _runtime_resize_message_buffer(size_t count);
int _runtime_receive_record_payload(int fd, unsigned char* dst, size_t dst_len);
int _runtime_reopen_cached_descriptor(int fd, unsigned char* dst, size_t dst_len);
int _runtime_route_by_partition_key(const char* route_key, int policy_id);
int _runtime_process_protocol_task(int fd, const char* fallback_key,
                                      unsigned char* out, size_t out_len);
uint32_t _runtime_update_metric_counter(uint32_t delta);

int _peer_process_session_message(int listen_fd, int work_fd, int peer_protocol,
                                unsigned char* out, size_t out_len);
int _peer_prepare_label_cache(unsigned int element_count);
int _peer_decode_header_window(const unsigned char* wire, size_t wire_len,
                                         unsigned char* out, size_t out_len);
int _peer_receive_session_frame(int fd, unsigned char* dst, size_t want);
int _peer_bridge_descriptor(int reliable_fd);
int _peer_route_protocol_context(int detected_protocol, int auth_level);
int _peer_prepare_retry_context(int retry_mode);
int _peer_expand_task_table(size_t task_index);
int _peer_select_version_window(const unsigned char* report, size_t len);
int _peer_publish_shared_session(int resource_id, int close_now);
int _peer_send_control_reply(int peer_fd, const unsigned char* payload, size_t len);
int _peer_export_descriptor_token(int listen_fd, int work_fd);

int _runtime_accept_session_frame(int shm_fd, const char* shm_name,
                                  const unsigned char* wire,
                                  size_t wire_len,
                                  unsigned char* out,
                                  size_t out_len);
int _runtime_refresh_worker_context(size_t block_size, const char* worker_name,
                                    uint32_t worker_id, int active_tasks);
int _runtime_apply_memory_plan(const char* segment_name, uint32_t mode,
                               uint64_t file_size, uint64_t map_size);
int _runtime_apply_pool_plan(uint32_t lcore_limit, uint32_t configured_lcores);
int _runtime_publish_process_record(uint32_t user_proc_id, uint32_t pid,
                                    const char* proc_name);
int _runtime_dispatch_event_cycle(int same_core, int fast_mode,
                                  int destroy_in_callback);
int _runtime_handle_fault_signal(int sig, void* ucontext, int hold_sem);
int _runtime_shutdown_local_session(const char* path, int project_id,
                                    size_t reserve_size);
int _runtime_init_sleep_window(int fd, int start_sec);
int _runtime_close_thread_cache(size_t block_size);
size_t _runtime_find_bitmap_delta(const unsigned char* input, size_t len);
uint32_t _runtime_read_lock_owner(uint32_t reader_pid);
int _runtime_release_packet_pool(int active_tasks);
uint64_t _runtime_read_timer_ticks(uint32_t lcore_id);
int _runtime_prepare_worker_label(const char* thread_name, uint32_t id);
int _runtime_enqueue_rcu_batch(int need_judge_pending, int callback_id);
int _runtime_rebuild_available_list(uint32_t configured_lcores);
void* _runtime_map_reserved_region(uint32_t mode, uint64_t file_size,
                                               uint64_t map_size);
int _runtime_note_module_ready(int already_initialized);
uint32_t _runtime_walk_arena_groups(uint32_t max_partition);
int _runtime_schedule_rcu_release(int use_qrcu, void* rcu, void* cb);
uint32_t _runtime_claim_process_slot(uint32_t user_proc_id, uint32_t pid,
                                        const char* proc_name);
int _runtime_open_named_segment(const char* shm_name, uint32_t requested_perm);
int _runtime_capture_signal_stack(int sig, void* ucontext);
int _runtime_queue_local_flush(int same_core, int fast_mode);
void* _runtime_create_shared_zone(const char* name, size_t size);
int _runtime_cleanup_tls_reserve(size_t reserve_size, int tlscb_ready);
void* _runtime_map_linked_segment(const char* real_path,
                                         const char* link_path,
                                         size_t shm_size);
int _runtime_release_hash_node(size_t node_size, int use_header_pool);
int _runtime_mark_process_online(int identity, uint32_t logic_proc_id);
int _runtime_make_shared_key(const char* path, int project_id);
int _runtime_cancel_wheel_timer(int call_from_callback);
int _runtime_write_exception_record(int sig, int hold_sem);
int _runtime_finish_current_event(int destroy_in_callback);

#endif
