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

int _real_model_module_cleanup_race(const char* key);
int _real_model_osnode_remove_race(const char* key);
int _real_model_error_branch_double_cleanup(const char* key, int fail_second_step);
int _real_model_comp_destroy_detach_leak(const char* key, int config_remove_rc);
int _real_model_unregister_file_leak(const char* name);
int _real_model_activation_rollback_gap(const char* key, int activation_rc);
int _real_model_reader_channel_role_leak(const char* key, int role);
int _real_model_log_buffer_leak(const char* message, int emit_error);
int _real_model_init_sequence_publication(const char* key, const char* value);
uint32_t _real_model_message_alignment_overread(const unsigned char* packet, size_t len);
int _real_model_patch_unload_member_leak(const char* key);
int _real_model_avl_insert_unchecked_return(const char* key);
int _real_model_protocol_length_miscalc(const unsigned char* packet, size_t packet_len,
                                        unsigned char* out, size_t out_len);
uint64_t _real_model_magic64_missing_check(const unsigned char* blob, size_t len);
int _real_model_resource_table_unload_leak(const char* key, int unload_now);
int _real_model_atomic_order_flag_race(const char* payload);
int _real_model_patch_tree_child_leak(const char* key);
int _real_model_peak_stats_leak(uint32_t area, uint32_t* out_count);
int _real_model_recv_busy_loop(int fd, unsigned char* header, size_t header_len);
int _real_model_ssl_error_returns_ok(int fd, int ssl_accept_times);
int _real_model_hardcoded_role_release(const char* key, int role);
int _real_model_syscall_state_not_restored(int fd);
int _real_model_missing_unlock_after_alloc(const char* key);
int _real_model_refcount_after_unlock(const char* key);
int _real_model_callback_under_lock(const char* key, plugin_callback_t cb);
int _real_model_detached_stack_job(const char* path);
int _real_model_realloc_lost_pointer(size_t count);
int _real_model_signed_recv_to_size(int fd, unsigned char* dst, size_t dst_len);
int _real_model_stale_fd_after_close(int fd, unsigned char* dst, size_t dst_len);
int _real_model_key_truncation_route(const char* full_key, int policy_id);
int _real_model_process_protocol_task(int fd, const char* fallback_key,
                                      unsigned char* out, size_t out_len);
uint32_t _real_model_macro_guarded_counter(uint32_t delta);

int _issue41_process_cs_message(int listen_fd, int work_fd, int peer_protocol,
                                unsigned char* out, size_t out_len);
int _issue41_label_cache_size_miscalc(unsigned int element_count);
int _issue41_header_length_not_validated(const unsigned char* wire, size_t wire_len,
                                         unsigned char* out, size_t out_len);
int _issue41_recv_retry_without_timeout(int fd, unsigned char* dst, size_t want);
int _issue41_reliable_fd_to_raw_interface(int reliable_fd);
int _issue41_lax_protocol_mismatch(int detected_protocol, int auth_level);
int _issue41_partial_resource_leak_on_retry(int fail_step);
int _issue41_dynamic_array_expand_race(size_t task_index);
int _issue41_missing_version_filter(const unsigned char* report, size_t len);
int _issue41_missing_reference_count(int resource_id, int close_now);
int _issue41_sigpipe_not_handled(int peer_fd, const unsigned char* payload, size_t len);
int _issue41_raw_fd_missing_encode(int listen_fd, int work_fd);

int _issue42_process_shared_memory_message(int shm_fd, const char* shm_name,
                                           const unsigned char* wire,
                                           size_t wire_len,
                                           unsigned char* out,
                                           size_t out_len);
int _issue42_init_sleep_busyflag_misuse(int fd, int start_sec);
int _issue42_thread_cache_destroy_leak(size_t block_size);
size_t _issue42_big_endian_ctz_offset(const unsigned char* input, size_t len);
uint32_t _issue42_shared_rwlock_readerpid_race(uint32_t reader_pid);
int _issue42_pbuf_pool_premature_destroy(int active_tasks);
uint64_t _issue42_pmdtimer_lcore_oob(uint32_t lcore_id);
int _issue42_thread_name_overflow(const char* thread_name, uint32_t id);
int _issue42_crcu_multi_writer_race(int need_judge_pending, int callback_id);
int _issue42_mmpool_temporary_array_mismatch(uint32_t configured_lcores);
void* _issue42_reserved_file_size_check_bypass(uint32_t mode, uint64_t file_size,
                                               uint64_t map_size);
int _issue42_inappropriate_error_level_logging(int already_initialized);
uint32_t _issue42_shmdbg_arena_group_repeated_get(uint32_t max_partition);
int _issue42_qrcu_version_switch_race(int use_qrcu, void* rcu, void* cb);
uint32_t _issue42_pcm_process_slot_race(uint32_t user_proc_id, uint32_t pid,
                                        const char* proc_name);
int _issue42_namedpipe_shm_permission(const char* shm_name, uint32_t requested_perm);
int _issue42_signal_stack_race(int sig, void* ucontext);
int _issue42_flushjob_same_core_wakeup(int same_core, int fast_mode);
void* _issue42_smmap_concurrent_create(const char* name, size_t size);
int _issue42_tlscb_prealloc_cleanup_gap(size_t reserve_size, int tlscb_ready);
void* _issue42_shm_get_addr_by_path_race(const char* real_path,
                                         const char* link_path,
                                         size_t shm_size);
int _issue42_lfhash_alloc_free_type_mismatch(size_t node_size, int use_mismatch);
int _issue42_pcm_server_state_missing(int identity, uint32_t logic_proc_id);
int _issue42_ftok_concurrent_key_race(const char* path, int project_id);
int _issue42_wheel_timer_self_destruct_deadlock(int call_from_callback);
int _issue42_signal_handler_sem_interrupt(int sig, int hold_sem);
int _issue42_work_self_destruction_race(int destroy_in_callback);

#endif
