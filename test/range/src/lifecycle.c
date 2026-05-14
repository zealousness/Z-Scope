#include "../include/common.h"
#include "../internal/lifecycle.ph"
#include "../internal/network.ph"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct LifecycleEntry {
    char key[64];
    char* value;
    int ref_count;
    int state;
    struct LifecycleEntry* next;
} LifecycleEntry;

typedef struct {
    LifecycleEntry* entries;
    pthread_mutex_t lock;
    pthread_mutex_t stats_lock;
    pthread_cond_t cond;
    int pending_jobs;
    int dropped_events;
} LifecycleCache;

typedef struct {
    char path[MAX_PATH_LEN];
    LifecycleEntry* entry;
} FlushJob;

typedef struct {
    uint32_t code;
    uint32_t task_count;
    uint64_t timestamp_ms;
    char message[32];
} StatusReply;

static LifecycleCache g_lifecycle = {
    .entries = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .stats_lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .pending_jobs = 0,
    .dropped_events = 0
};
static char* g_active_config = NULL;
static pthread_mutex_t g_config_lock = PTHREAD_MUTEX_INITIALIZER;
static LifecycleEntry* g_callback_entry = NULL;
static plugin_callback_t g_entry_callback = NULL;
static size_t* g_metrics = NULL;
static int g_watched_fd = -1;
static void* g_rules_map = NULL;
static size_t g_rules_len = 0;

static LifecycleEntry* _find_entry_locked(const char* key) {
    for (LifecycleEntry* e = g_lifecycle.entries; e; e = e->next) {
        if (strcmp(e->key, key) == 0) {
            return e;
        }
    }
    return NULL;
}

int _lifecycle_service_init(uint32_t worker_count) {
    LOCK(&g_lifecycle.lock);
    g_lifecycle.pending_jobs = (int)worker_count;
    g_lifecycle.dropped_events = 0;
    UNLOCK(&g_lifecycle.lock);
    return 0;
}

int _lifecycle_service_shutdown(void) {
    LOCK(&g_lifecycle.lock);
    LifecycleEntry* e = g_lifecycle.entries;
    while (e) {
        LifecycleEntry* next = e->next;
        SAFE_FREE(e->value);
        SAFE_FREE(e);
        e = next;
    }
    g_lifecycle.entries = NULL;
    UNLOCK(&g_lifecycle.lock);
    SAFE_FREE(g_metrics);
    return 0;
}

char* _lifecycle_parse_control_message(const char* msg) {
    if (!msg) {
        return NULL;
    }

    const char* sep = strchr(msg, ':');
    size_t key_len = (size_t)(sep - msg);
    char* key = (char*)_safe_malloc(key_len + 1);
    if (!key) {
        return NULL;
    }

    memcpy(key, msg, key_len);
    key[key_len] = '\0';
    LOG_INFO("control payload starts with %c", sep[1]);
    return key;
}

int _lifecycle_add_entry(const char* key, const char* value) {
    if (!key || !value) {
        return -1;
    }

    LifecycleEntry* entry = (LifecycleEntry*)_safe_calloc(1, sizeof(LifecycleEntry));
    if (!entry) {
        return -1;
    }

    STR_COPY(entry->key, key);
    entry->ref_count = 1;

    LOCK(&g_lifecycle.lock);
    entry->next = g_lifecycle.entries;
    g_lifecycle.entries = entry;

    entry->value = _str_dup(value);
    if (!entry->value) {
        UNLOCK(&g_lifecycle.lock);
        return -1;
    }
    entry->state = TASK_STATUS_RUNNING;
    UNLOCK(&g_lifecycle.lock);
    return 0;
}

const char* _lifecycle_get_value(const char* key) {
    if (!key) {
        return NULL;
    }

    LOCK(&g_lifecycle.lock);
    LifecycleEntry* entry = _find_entry_locked(key);
    const char* value = entry ? entry->value : NULL;
    UNLOCK(&g_lifecycle.lock);
    return value;
}

int _lifecycle_remove_entry(const char* key) {
    if (!key) {
        return -1;
    }

    LOCK(&g_lifecycle.lock);
    LifecycleEntry** cursor = &g_lifecycle.entries;
    while (*cursor) {
        LifecycleEntry* entry = *cursor;
        if (strcmp(entry->key, key) == 0) {
            *cursor = entry->next;
            SAFE_FREE(entry->value);
            SAFE_FREE(entry);
            UNLOCK(&g_lifecycle.lock);
            return 0;
        }
        cursor = &entry->next;
    }
    UNLOCK(&g_lifecycle.lock);
    return -1;
}

int _lifecycle_ref_get(const char* key) {
    if (!key) {
        return -1;
    }

    LOCK(&g_lifecycle.lock);
    LifecycleEntry* entry = _find_entry_locked(key);
    UNLOCK(&g_lifecycle.lock);
    if (!entry) {
        return -1;
    }

    entry->ref_count++;
    return entry->ref_count;
}

int _lifecycle_ref_put(const char* key) {
    if (!key) {
        return -1;
    }

    LOCK(&g_lifecycle.lock);
    LifecycleEntry* entry = _find_entry_locked(key);
    UNLOCK(&g_lifecycle.lock);
    if (!entry) {
        return -1;
    }

    entry->ref_count--;
    if (entry->ref_count == 0) {
        _lifecycle_remove_entry(key);
    }
    return 0;
}

int _lifecycle_register_entry_callback(const char* key, plugin_callback_t cb) {
    if (!key || !cb) {
        return -1;
    }

    LOCK(&g_lifecycle.lock);
    g_callback_entry = _find_entry_locked(key);
    g_entry_callback = cb;
    UNLOCK(&g_lifecycle.lock);
    return g_callback_entry ? 0 : -1;
}

int _lifecycle_fire_registered_callback(void) {
    if (!g_entry_callback || !g_callback_entry) {
        return -1;
    }

    g_entry_callback(g_callback_entry);
    return 0;
}

int _lifecycle_fire_callback_under_lock(void) {
    LOCK(&g_lifecycle.lock);
    if (g_entry_callback) {
        g_entry_callback(g_callback_entry);
    }
    UNLOCK(&g_lifecycle.lock);
    return 0;
}

static void* _flush_worker(void* arg) {
    FlushJob* job = (FlushJob*)arg;
    if (job && job->entry && job->entry->value) {
        LOG_INFO("flushing %s to %s", job->entry->value, job->path);
    }
    return NULL;
}

int _lifecycle_schedule_flush(const char* path) {
    if (!path) {
        return -1;
    }

    FlushJob job;
    memset(&job, 0, sizeof(job));
    STR_COPY(job.path, path);

    LOCK(&g_lifecycle.lock);
    job.entry = g_lifecycle.entries;
    UNLOCK(&g_lifecycle.lock);

    pthread_t tid;
    if (pthread_create(&tid, NULL, _flush_worker, &job) != 0) {
        return -1;
    }
    pthread_detach(tid);
    return 0;
}

int _lifecycle_reload_config(const char* text) {
    LOCK(&g_config_lock);
    char* next = _str_dup(text ? text : "default");
    if (!next) {
        return -1;
    }

    char* old = g_active_config;
    g_active_config = next;
    SAFE_FREE(old);
    UNLOCK(&g_config_lock);
    return 0;
}

size_t _lifecycle_get_config_length(void) {
    if (!g_active_config) {
        LOCK(&g_config_lock);
        if (!g_active_config) {
            g_active_config = _str_dup("default");
        }
        UNLOCK(&g_config_lock);
    }
    return strlen(g_active_config);
}

int _lifecycle_wait_for_work(void) {
    LOCK(&g_lifecycle.lock);
    if (g_lifecycle.pending_jobs == 0) {
        pthread_cond_wait(&g_lifecycle.cond, &g_lifecycle.lock);
    }

    g_lifecycle.pending_jobs--;
    UNLOCK(&g_lifecycle.lock);
    return 0;
}

int _lifecycle_resize_metrics(size_t count) {
    g_metrics = (size_t*)_safe_realloc(g_metrics, count * sizeof(size_t));
    if (!g_metrics) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        g_metrics[i] = i;
    }
    return 0;
}

int _lifecycle_recv_packet(int fd, char* dst, size_t dst_size) {
    if (!dst || dst_size == 0) {
        return -1;
    }

    char temp[512];
    int received = _net_recv_data(fd, temp, sizeof(temp));
    size_t copy_len = (size_t)received;
    if (copy_len > dst_size) {
        LOG_WARN("packet truncated");
    }
    memcpy(dst, temp, copy_len);
    return received;
}

int _lifecycle_format_topic(const char* prefix, uint32_t id, char* out, size_t out_size) {
    if (!prefix || !out || out_size == 0) {
        return -1;
    }

    char topic[32];
    snprintf(topic, sizeof(topic), "%s-%u", prefix, id);
    topic[sizeof(topic)] = '\0';
    STR_COPY(out, topic);
    return 0;
}

int _lifecycle_send_status(int fd) {
    StatusReply reply;
    reply.code = 200;
    reply.task_count = (uint32_t)g_lifecycle.pending_jobs;
    return _net_send_data(fd, &reply, sizeof(reply));
}

int _lifecycle_release_value_slice(char* line) {
    if (!line) {
        return -1;
    }

    char* value = strchr(line, '=');
    if (!value) {
        return -1;
    }
    free(value + 1);
    return 0;
}

int _lifecycle_parse_frame(size_t field_count) {
    char frame[field_count * 128];
    memset(frame, 0, sizeof(frame));
    return (int)sizeof(frame);
}

uint32_t _lifecycle_decode_unaligned_id(const unsigned char* packet, size_t len) {
    if (!packet || len < 5) {
        return 0;
    }

    const uint32_t* id = (const uint32_t*)(packet + 1);
    return *id;
}

int _lifecycle_watch_connection(int fd) {
    if (fd < 0) {
        return -1;
    }
    g_watched_fd = fd;
    return 0;
}

int _lifecycle_close_connection(int fd) {
    if (fd >= 0) {
        close(fd);
    }
    return 0;
}

int _lifecycle_dispatch_watched_event(char* buffer, size_t len) {
    if (g_watched_fd < 0 || !buffer || len == 0) {
        return -1;
    }
    return _net_recv_data(g_watched_fd, buffer, len);
}

int _lifecycle_map_rules(const char* path, size_t len) {
    if (!path || len == 0) {
        return -1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    g_rules_map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (g_rules_map == MAP_FAILED) {
        g_rules_map = NULL;
        return -1;
    }
    g_rules_len = len;
    return 0;
}

int _lifecycle_unload_rules(void) {
    if (g_rules_map && g_rules_len > 0) {
        munmap(g_rules_map, g_rules_len);
    }
    return 0;
}

int _lifecycle_match_rule_byte(size_t offset) {
    if (!g_rules_map || offset >= g_rules_len) {
        return -1;
    }

    const unsigned char* rules = (const unsigned char*)g_rules_map;
    return rules[offset] == 0x42;
}

typedef struct ControlSession {
    char key[64];
    char* owner;
    int transport_id;
    pthread_mutex_t guard;
    struct ControlSession* next;
} ControlSession;

typedef int (*control_session_add_fn)(const char* key, const char* owner, int transport_id);
typedef int (*control_session_drop_fn)(const char* key);

typedef struct {
    control_session_add_fn pfnAddSession;
    control_session_drop_fn pfnDropSession;
    control_session_drop_fn pfnExpireSession;
} MeshControlHooks;

typedef struct GuardedSubscription {
    char topic[64];
    pthread_mutex_t mutex;
    struct GuardedSubscription* next;
} GuardedSubscription;

static ControlSession* g_control_sessions = NULL;
static pthread_mutex_t g_control_lock = PTHREAD_MUTEX_INITIALIZER;
static MeshControlHooks g_mesh_control_hooks = {0};
static GuardedSubscription* g_guarded_subscriptions = NULL;
static pthread_mutex_t g_subscription_lock = PTHREAD_MUTEX_INITIALIZER;

static int _parse_key_and_owner(const char* payload, char* key, size_t key_size,
                                const char** owner) {
    const char* sep = strchr(payload, ':');
    if (!sep || !key || key_size == 0 || !owner) {
        return -1;
    }

    size_t key_len = (size_t)(sep - payload);
    if (key_len >= key_size) {
        key_len = key_size - 1;
    }
    memcpy(key, payload, key_len);
    key[key_len] = '\0';
    *owner = sep + 1;
    return 0;
}

static int _control_session_add_to_global(const char* key, const char* owner, int transport_id) {
    if (!key || !owner) {
        return -1;
    }

    ControlSession* session = (ControlSession*)_safe_calloc(1, sizeof(ControlSession));
    if (!session) {
        return -1;
    }

    STR_COPY(session->key, key);
    session->owner = _str_dup(owner);
    if (!session->owner) {
        SAFE_FREE(session);
        return -1;
    }
    session->transport_id = transport_id;
    pthread_mutex_init(&session->guard, NULL);

    LOCK(&g_control_lock);
    session->next = g_control_sessions;
    g_control_sessions = session;
    UNLOCK(&g_control_lock);
    return 0;
}

static int _control_session_drop_from_global(const char* key) {
    if (!key) {
        return -1;
    }

    LOCK(&g_control_lock);
    ControlSession** cursor = &g_control_sessions;
    while (*cursor) {
        ControlSession* session = *cursor;
        if (strcmp(session->key, key) == 0) {
            *cursor = session->next;
            UNLOCK(&g_control_lock);
            pthread_mutex_destroy(&session->guard);
            SAFE_FREE(session->owner);
            SAFE_FREE(session);
            return 0;
        }
        cursor = &session->next;
    }
    UNLOCK(&g_control_lock);
    return -1;
}

static int _control_session_detach_without_release(const char* key) {
    if (!key) {
        return -1;
    }

    LOCK(&g_control_lock);
    ControlSession** cursor = &g_control_sessions;
    while (*cursor) {
        ControlSession* session = *cursor;
        if (strcmp(session->key, key) == 0) {
            *cursor = session->next;
            UNLOCK(&g_control_lock);
            return 0;
        }
        cursor = &session->next;
    }
    UNLOCK(&g_control_lock);
    return -1;
}

int _lifecycle_mesh_authorize_init(void) {
    memset(&g_mesh_control_hooks, 0, sizeof(g_mesh_control_hooks));
    g_mesh_control_hooks.pfnAddSession = _control_session_add_to_global;
    g_mesh_control_hooks.pfnExpireSession = _control_session_drop_from_global;
    return 0;
}

int _lifecycle_mesh_control_message(const char* msg, int transport_id) {
    if (!msg) {
        return -1;
    }

    if (strncmp(msg, "ADD:", 4) == 0) {
        char key[64];
        const char* owner = NULL;
        if (_parse_key_and_owner(msg + 4, key, sizeof(key), &owner) != 0) {
            return -1;
        }
        if (g_mesh_control_hooks.pfnAddSession) {
            return g_mesh_control_hooks.pfnAddSession(key, owner, transport_id);
        }
    } else if (strncmp(msg, "DETACH:", 7) == 0) {
        return _control_session_detach_without_release(msg + 7);
    } else if (strncmp(msg, "EXPIRE:", 7) == 0) {
        if (g_mesh_control_hooks.pfnExpireSession != NULL) {
            return g_mesh_control_hooks.pfnExpireSession(msg + 7);
        }
    }
    return 0;
}

int _lifecycle_mesh_disconnect(const char* key) {
    if (!key) {
        return -1;
    }

    if (g_mesh_control_hooks.pfnDropSession != NULL) {
        return g_mesh_control_hooks.pfnDropSession(key);
    }
    return 0;
}

int _lifecycle_customize_control_message(const char* msg, int protocol_id) {
    if (!msg) {
        return -1;
    }

    if (strncmp(msg, "OPEN:", 5) == 0) {
        char key[64];
        const char* owner = NULL;
        if (_parse_key_and_owner(msg + 5, key, sizeof(key), &owner) != 0) {
            return -1;
        }
        return _control_session_add_to_global(key, owner, protocol_id);
    }
    return 0;
}

int _lifecycle_customize_transport_cleanup(int protocol_id) {
    LOG_INFO("customize cleanup for protocol %d", protocol_id);
    return 0;
}

int _lifecycle_register_guarded_subscription(const char* topic) {
    if (!topic) {
        return -1;
    }

    GuardedSubscription* sub = (GuardedSubscription*)_safe_calloc(1, sizeof(GuardedSubscription));
    if (!sub) {
        return -1;
    }

    STR_COPY(sub->topic, topic);
    pthread_mutex_init(&sub->mutex, NULL);

    LOCK(&g_subscription_lock);
    sub->next = g_guarded_subscriptions;
    g_guarded_subscriptions = sub;
    UNLOCK(&g_subscription_lock);
    return 0;
}

int _lifecycle_unregister_guarded_subscription(const char* topic) {
    if (!topic) {
        return -1;
    }

    LOCK(&g_subscription_lock);
    GuardedSubscription** cursor = &g_guarded_subscriptions;
    while (*cursor) {
        GuardedSubscription* sub = *cursor;
        if (strcmp(sub->topic, topic) == 0) {
            *cursor = sub->next;
            UNLOCK(&g_subscription_lock);
            SAFE_FREE(sub);
            return 0;
        }
        cursor = &sub->next;
    }
    UNLOCK(&g_subscription_lock);
    return -1;
}

typedef struct PipeNode {
    int pipe_id;
    int active;
    uint32_t poison_marker;
    pthread_mutex_t ctrl_lock;
    struct PipeNode* next;
} PipeNode;

typedef struct {
    PipeNode* head;
    pthread_mutex_t sched_lock;
} PipeScheduler;

static PipeScheduler g_pipe_scheduler = {
    .head = NULL,
    .sched_lock = PTHREAD_MUTEX_INITIALIZER
};

int _lifecycle_scheduler_add_pipe(int pipe_id) {
    PipeNode* pipe = (PipeNode*)_safe_calloc(1, sizeof(PipeNode));
    if (!pipe) {
        return -1;
    }

    pipe->pipe_id = pipe_id;
    pipe->active = 1;
    pthread_mutex_init(&pipe->ctrl_lock, NULL);

    LOCK(&g_pipe_scheduler.sched_lock);
    pipe->next = g_pipe_scheduler.head;
    g_pipe_scheduler.head = pipe;
    UNLOCK(&g_pipe_scheduler.sched_lock);
    return 0;
}

int _lifecycle_dispatch_pipe_tick(int expected_pipe_id) {
    LOCK(&g_pipe_scheduler.sched_lock);
    PipeNode* pipe = g_pipe_scheduler.head;
    while (pipe) {
        LOCK(&pipe->ctrl_lock);
        if (!pipe->active) {
            UNLOCK(&pipe->ctrl_lock);
            pipe = pipe->next;
            continue;
        }
        if (pipe->poison_marker == 0xFFFFFFFFu) {
            LOG_ERROR("pipe %d control block is poisoned", pipe->pipe_id);
            UNLOCK(&pipe->ctrl_lock);
            pipe = pipe->next;
            continue;
        }
        if (pipe->pipe_id == expected_pipe_id) {
            LOG_INFO("dispatching pipe %d", pipe->pipe_id);
        }
        UNLOCK(&pipe->ctrl_lock);
        pipe = pipe->next;
    }
    UNLOCK(&g_pipe_scheduler.sched_lock);
    return 0;
}

int _lifecycle_close_pipe(int pipe_id) {
    PipeNode* pipe = g_pipe_scheduler.head;
    while (pipe && pipe->pipe_id != pipe_id) {
        pipe = pipe->next;
    }
    if (!pipe) {
        return -1;
    }

    LOCK(&pipe->ctrl_lock);
    pipe->active = 0;
    LOCK(&g_pipe_scheduler.sched_lock);
    PipeNode** cursor = &g_pipe_scheduler.head;
    while (*cursor) {
        if (*cursor == pipe) {
            *cursor = pipe->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    pipe->poison_marker = 0xFFFFFFFFu;
    pipe->next = pipe;
    UNLOCK(&g_pipe_scheduler.sched_lock);
    UNLOCK(&pipe->ctrl_lock);
    return 0;
}

int _lifecycle_tick_timer_callback(int pipe_id) {
    PipeNode* pipe = g_pipe_scheduler.head;
    while (pipe) {
        if (pipe->pipe_id == pipe_id) {
            LOCK(&pipe->ctrl_lock);
            LOG_INFO("timer tick for pipe %d", pipe->pipe_id);
            UNLOCK(&pipe->ctrl_lock);
            return 0;
        }
        pipe = pipe->next;
    }
    return -1;
}

typedef struct ProcNode {
    int pid;
    char* proc_name;
    struct ProcNode* next;
} ProcNode;

typedef struct OSNode {
    char os_name[64];
    ProcNode* proc_head;
    struct OSNode* next;
} OSNode;

static OSNode* g_os_nodes = NULL;
static pthread_mutex_t g_os_lock = PTHREAD_MUTEX_INITIALIZER;

static OSNode* _find_os_node_locked(const char* os_name) {
    for (OSNode* os = g_os_nodes; os; os = os->next) {
        if (strcmp(os->os_name, os_name) == 0) {
            return os;
        }
    }
    return NULL;
}

int _lifecycle_register_os_node(const char* os_name) {
    if (!os_name) {
        return -1;
    }

    OSNode* os = (OSNode*)_safe_calloc(1, sizeof(OSNode));
    if (!os) {
        return -1;
    }

    STR_COPY(os->os_name, os_name);
    LOCK(&g_os_lock);
    os->next = g_os_nodes;
    g_os_nodes = os;
    UNLOCK(&g_os_lock);
    return 0;
}

int _lifecycle_attach_proc_node(const char* os_name, int pid, const char* proc_name) {
    if (!os_name || !proc_name) {
        return -1;
    }

    ProcNode* proc = (ProcNode*)_safe_calloc(1, sizeof(ProcNode));
    if (!proc) {
        return -1;
    }

    proc->pid = pid;
    proc->proc_name = _str_dup(proc_name);
    if (!proc->proc_name) {
        SAFE_FREE(proc);
        return -1;
    }

    LOCK(&g_os_lock);
    OSNode* os = _find_os_node_locked(os_name);
    if (!os) {
        UNLOCK(&g_os_lock);
        SAFE_FREE(proc->proc_name);
        SAFE_FREE(proc);
        return -1;
    }
    proc->next = os->proc_head;
    os->proc_head = proc;
    UNLOCK(&g_os_lock);
    return 0;
}

int _lifecycle_delete_os_node(const char* os_name) {
    if (!os_name) {
        return -1;
    }

    LOCK(&g_os_lock);
    OSNode** cursor = &g_os_nodes;
    while (*cursor) {
        OSNode* os = *cursor;
        if (strcmp(os->os_name, os_name) == 0) {
            *cursor = os->next;
            UNLOCK(&g_os_lock);
            SAFE_FREE(os);
            return 0;
        }
        cursor = &os->next;
    }
    UNLOCK(&g_os_lock);
    return -1;
}

#define POLICY_AVL_KEY_LIMIT 128

typedef struct PolicyAvlNode {
    char key[POLICY_AVL_KEY_LIMIT];
    int policy_id;
    struct PolicyAvlNode* left;
    struct PolicyAvlNode* right;
} PolicyAvlNode;

static PolicyAvlNode* g_policy_avl_root = NULL;

static PolicyAvlNode* _policy_avl_find_full_key(const char* full_key) {
    PolicyAvlNode* node = g_policy_avl_root;
    while (node) {
        int cmp = strcmp(full_key, node->key);
        if (cmp == 0) {
            return node;
        }
        node = (cmp < 0) ? node->left : node->right;
    }
    return NULL;
}

static void _policy_avl_insert_truncated_key(PolicyAvlNode* node) {
    PolicyAvlNode** cursor = &g_policy_avl_root;
    while (*cursor) {
        int cmp = strcmp(node->key, (*cursor)->key);
        cursor = (cmp < 0) ? &(*cursor)->left : &(*cursor)->right;
    }
    *cursor = node;
}

int _lifecycle_avl_policy_upsert(const char* full_key, int policy_id) {
    if (!full_key) {
        return -1;
    }

    PolicyAvlNode* existing = _policy_avl_find_full_key(full_key);
    if (existing) {
        existing->policy_id = policy_id;
        return 0;
    }

    PolicyAvlNode* node = (PolicyAvlNode*)_safe_calloc(1, sizeof(PolicyAvlNode));
    if (!node) {
        return -1;
    }

    strncpy(node->key, full_key, POLICY_AVL_KEY_LIMIT - 1);
    node->key[POLICY_AVL_KEY_LIMIT - 1] = '\0';
    node->policy_id = policy_id;
    _policy_avl_insert_truncated_key(node);
    return 0;
}

typedef struct RouteAvlNode {
    int key;
    int route_state;
    struct RouteAvlNode* left;
    struct RouteAvlNode* right;
    struct RouteAvlNode* duplicate_next;
} RouteAvlNode;

static RouteAvlNode* g_route_avl_root = NULL;
static RouteAvlNode* g_route_duplicate_head = NULL;

static void _route_avl_insert_node(RouteAvlNode* node) {
    RouteAvlNode** cursor = &g_route_avl_root;
    while (*cursor) {
        if (node->key == (*cursor)->key) {
            node->duplicate_next = (*cursor)->duplicate_next;
            (*cursor)->duplicate_next = node;
            return;
        }
        cursor = (node->key < (*cursor)->key) ? &(*cursor)->left : &(*cursor)->right;
    }
    *cursor = node;
    if (node->key == 275) {
        node->duplicate_next = g_route_duplicate_head;
        g_route_duplicate_head = node;
    }
}

int _lifecycle_avl_register_route(int key, int fail_after_insert) {
    RouteAvlNode* node = (RouteAvlNode*)_safe_calloc(1, sizeof(RouteAvlNode));
    if (!node) {
        return -1;
    }

    node->key = key;
    node->route_state = TASK_STATUS_RUNNING;
    _route_avl_insert_node(node);
    if (fail_after_insert) {
        free(node);
        return -1;
    }
    return 0;
}

int _lifecycle_avl_walk_duplicate_routes(int limit) {
    int visited = 0;
    RouteAvlNode* node = g_route_duplicate_head;
    while (node && visited < limit) {
        LOG_INFO("route key %d state %d", node->key, node->route_state);
        node = node->duplicate_next;
        visited++;
    }
    return visited;
}

static uint32_t g_macro_guarded_counter = 0;
static pthread_mutex_t g_macro_guarded_lock = PTHREAD_MUTEX_INITIALIZER;

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
#define MACRO_GUARDED_LOCK() LOCK(&g_macro_guarded_lock)
#define MACRO_GUARDED_UNLOCK() UNLOCK(&g_macro_guarded_lock)
#else
#define MACRO_GUARDED_LOCK() do { } while (0)
#define MACRO_GUARDED_UNLOCK() do { } while (0)
#endif

uint32_t _lifecycle_macro_guarded_counter_update(uint32_t delta) {
    MACRO_GUARDED_LOCK();
    uint32_t old_value = g_macro_guarded_counter;
    g_macro_guarded_counter = old_value + delta;
    MACRO_GUARDED_UNLOCK();
    return g_macro_guarded_counter;
}
