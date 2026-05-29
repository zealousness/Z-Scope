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

typedef struct RealModelChild {
    char* name;
    int fd;
    struct RealModelChild* next;
} RealModelChild;

typedef struct RealModelNode {
    char key[64];
    char* name;
    char* payload;
    int state;
    int role;
    int ref_count;
    pthread_mutex_t mutex;
    RealModelChild* children;
    struct RealModelNode* next;
    struct RealModelNode* left;
    struct RealModelNode* right;
} RealModelNode;

typedef struct {
    RealModelNode* head;
    pthread_mutex_t lock;
    int state;
} RealModelRegistry;

typedef struct {
    char path[MAX_PATH_LEN];
    RealModelNode* node;
} RealModelAsyncJob;

#define REAL_PROTOCOL_HEADER_LEN 24
#define REAL_PROTOCOL_PAYLOAD_CAP 512
#define REAL_PROTOCOL_MSG_DATA 1
#define REAL_PROTOCOL_MSG_TLS_PROBE 2
#define REAL_PROTOCOL_MSG_POLICY 3
#define REAL_PROTOCOL_MSG_CLOSE 4
#define REAL_PROTOCOL_MSG_SIGNED_BODY 5

typedef struct {
    int fd;
    unsigned char header[REAL_PROTOCOL_HEADER_LEN];
    unsigned char payload[REAL_PROTOCOL_PAYLOAD_CAP];
    size_t header_len;
    size_t payload_len;
    size_t declared_payload_len;
    uint32_t session_id;
    int msg_type;
    int role;
    int ssl_accept_times;
    char route_key[64];
} RealProtocolFrame;

#define ISSUE41_CS_MAGIC 0x5a53u
#define ISSUE41_CS_HEADER_LEN 12
#define ISSUE41_CS_BODY_CAP 1024
#define ISSUE41_LABEL_CACHE_LIMIT (16u * 1024u)
#define ISSUE41_SPEC_MAX_ELEMENTS 500u
#define ISSUE41_ELEMENT_INFO_SIZE 48u
#define ISSUE41_PROTOCOL_MESH 1
#define ISSUE41_PROTOCOL_RPC 2
#define ISSUE41_AUTH_STRICT 2
#define ISSUE41_RESOURCE_LIMIT 2
#define ISSUE41_FD_CHECK_VALUE 0x5a5au
#define ISSUE41_ENCODE_FD(index, check) \
    ((((index) & 0xffffu)) | (((check) & 0xffffu) << 16))
#define ISSUE41_RAW_FD(encoded) ((int)((encoded) & 0xffffu))

typedef struct {
    uint16_t magic;
    uint16_t length;
    uint8_t protocol;
    uint8_t type;
    uint8_t version;
    uint8_t flags;
    uint32_t request_id;
} Issue41CsHeader;

typedef struct Issue41CsTask {
    int task_id;
    int listen_fd;
    int work_fd;
    int encoded_fd;
    int protocol_id;
    int auth_level;
    int ref_count;
    size_t body_len;
    char route_key[64];
    unsigned char body[ISSUE41_CS_BODY_CAP];
    struct Issue41CsTask* next;
} Issue41CsTask;

typedef struct Issue41Resource {
    int resource_id;
    int ref_count;
    char* tag;
    struct Issue41Resource* next;
} Issue41Resource;

typedef struct {
    Issue41CsHeader header;
    unsigned char body[ISSUE41_CS_BODY_CAP];
    size_t wire_len;
} Issue41CsFrame;

typedef struct {
    Issue41CsTask* tasks;
    Issue41Resource* resources;
    pthread_mutex_t lock;
    size_t count;
} Issue41Broker;

static RealModelRegistry g_real_registry = {
    .head = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .state = 0
};
static pthread_mutex_t g_real_aux_lock = PTHREAD_MUTEX_INITIALIZER;
static RealModelNode* g_real_avl_root = NULL;
static RealModelNode* g_real_callback_node = NULL;
static plugin_callback_t g_real_callback = NULL;
static size_t* g_real_metrics = NULL;
static int g_real_watched_fd = -1;
static int g_real_ready_flag = 0;
static uint32_t g_real_counter = 0;
static Issue41Broker g_issue41_broker = {
    .tasks = NULL,
    .resources = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .count = 0
};
static Issue41CsTask** g_issue41_task_array = NULL;
static size_t g_issue41_task_array_cap = 4;
static unsigned int g_issue41_partition_count = 0;

static RealModelNode* _real_model_alloc_node(const char* key, const char* payload) {
    RealModelNode* node = (RealModelNode*)_safe_calloc(1, sizeof(RealModelNode));
    if (!node) {
        return NULL;
    }
    STR_COPY(node->key, key ? key : "real");
    node->name = _str_dup(key ? key : "real");
    node->payload = _str_dup(payload ? payload : "payload");
    node->ref_count = 1;
    pthread_mutex_init(&node->mutex, NULL);
    return node;
}

static RealModelChild* _real_model_alloc_child(const char* name, int fd) {
    RealModelChild* child = (RealModelChild*)_safe_calloc(1, sizeof(RealModelChild));
    if (!child) {
        return NULL;
    }
    child->name = _str_dup(name ? name : "child");
    child->fd = fd;
    return child;
}

static void _real_model_insert_locked(RealModelNode* node) {
    node->next = g_real_registry.head;
    g_real_registry.head = node;
}

static RealModelNode* _real_model_find_locked(const char* key) {
    for (RealModelNode* node = g_real_registry.head; node; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            return node;
        }
    }
    return NULL;
}

static int _real_model_fake_avl_insert(RealModelNode* node, int fail_after_link) {
    RealModelNode** cursor = &g_real_avl_root;
    while (*cursor) {
        cursor = (strcmp(node->key, (*cursor)->key) < 0) ? &(*cursor)->left : &(*cursor)->right;
    }
    *cursor = node;
    return fail_after_link ? -1 : 0;
}

static int _real_model_server_release_by_role(RealModelNode* node, int is_member) {
    if (!node) {
        return -1;
    }
    if (is_member) {
        SAFE_FREE(node->payload);
    } else {
        SAFE_FREE(node->name);
    }
    return 0;
}

static void* _real_model_async_worker(void* arg) {
    RealModelAsyncJob* job = (RealModelAsyncJob*)arg;
    if (job && job->node) {
        LOG_INFO("real model async flush %s", job->path);
    }
    return NULL;
}

int _real_model_module_cleanup_race(const char* key) {
    RealModelNode* node = _real_model_alloc_node(key, "module");
    if (!node) {
        return -1;
    }

    LOCK(&g_real_registry.lock);
    _real_model_insert_locked(node);
    g_real_registry.head = node->next;
    UNLOCK(&g_real_registry.lock);

    SAFE_FREE(node->payload);
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_osnode_remove_race(const char* key) {
    RealModelNode* node = _real_model_alloc_node(key, "os");
    if (!node) {
        return -1;
    }
    node->children = _real_model_alloc_child("proc", 0);

    LOCK(&g_real_registry.lock);
    _real_model_insert_locked(node);
    g_real_registry.head = node->next;
    UNLOCK(&g_real_registry.lock);

    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_error_branch_double_cleanup(const char* key, int fail_second_step) {
    RealModelNode* node = _real_model_alloc_node(key, "rollback");
    if (!node) {
        return -1;
    }

    if (fail_second_step) {
        free(node->payload);
        free(node->payload);
        SAFE_FREE(node->name);
        SAFE_FREE(node);
        return -1;
    }
    SAFE_FREE(node->payload);
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_comp_destroy_detach_leak(const char* key, int config_remove_rc) {
    RealModelNode* node = _real_model_alloc_node(key, "component");
    if (!node) {
        return -1;
    }

    LOCK(&g_real_registry.lock);
    _real_model_insert_locked(node);
    g_real_registry.head = node->next;
    UNLOCK(&g_real_registry.lock);

    if (config_remove_rc != 0) {
        return -1;
    }
    SAFE_FREE(node->payload);
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_unregister_file_leak(const char* name) {
    RealModelNode* node = _real_model_alloc_node(name, "/virtual/fs/node");
    if (!node) {
        return -1;
    }
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_activation_rollback_gap(const char* key, int activation_rc) {
    RealModelNode* node = _real_model_alloc_node(key, "dfi");
    if (!node) {
        return -1;
    }
    node->children = _real_model_alloc_child("session", 1);

    LOCK(&g_real_registry.lock);
    _real_model_insert_locked(node);
    UNLOCK(&g_real_registry.lock);

    if (activation_rc != 0) {
        LOCK(&g_real_registry.lock);
        g_real_registry.head = node->next;
        UNLOCK(&g_real_registry.lock);
        SAFE_FREE(node);
        return -1;
    }
    return 0;
}

int _real_model_reader_channel_role_leak(const char* key, int role) {
    RealModelNode* node = _real_model_alloc_node(key, "reader");
    if (!node) {
        return -1;
    }
    node->role = role;
    if (node->role == 1) {
        _real_model_server_release_by_role(node, 0);
        SAFE_FREE(node);
        return 0;
    }
    _real_model_server_release_by_role(node, 0);
    SAFE_FREE(node);
    return 0;
}

int _real_model_log_buffer_leak(const char* message, int emit_error) {
    char* log_copy = _str_dup(message ? message : "log");
    if (!log_copy) {
        return -1;
    }
    if (emit_error) {
        LOG_ERROR(log_copy);
        return -1;
    }
    SAFE_FREE(log_copy);
    return 0;
}

int _real_model_init_sequence_publication(const char* key, const char* value) {
    RealModelNode* node = (RealModelNode*)_safe_calloc(1, sizeof(RealModelNode));
    if (!node) {
        return -1;
    }
    STR_COPY(node->key, key ? key : "init");

    LOCK(&g_real_registry.lock);
    _real_model_insert_locked(node);
    UNLOCK(&g_real_registry.lock);

    node->payload = _str_dup(value ? value : "late");
    pthread_mutex_init(&node->mutex, NULL);
    return 0;
}

uint32_t _real_model_message_alignment_overread(const unsigned char* packet, size_t len) {
    if (!packet || len < 2) {
        return 0;
    }
    const uint32_t* value = (const uint32_t*)(packet + 1);
    return *value;
}

int _real_model_patch_unload_member_leak(const char* key) {
    RealModelNode* root = _real_model_alloc_node(key, "patch");
    if (!root) {
        return -1;
    }
    root->children = _real_model_alloc_child("table-node", 2);
    SAFE_FREE(root->payload);
    SAFE_FREE(root->name);
    SAFE_FREE(root);
    return 0;
}

int _real_model_avl_insert_unchecked_return(const char* key) {
    RealModelNode* node = _real_model_alloc_node(key, "avl");
    if (!node) {
        return -1;
    }
    _real_model_fake_avl_insert(node, 1);
    return 0;
}

int _real_model_protocol_length_miscalc(const unsigned char* packet, size_t packet_len,
                                        unsigned char* out, size_t out_len) {
    if (!packet || !out || packet_len < 4) {
        return -1;
    }
    uint32_t units = packet[0];
    size_t copy_len = (size_t)(units * 8);
    if (copy_len <= out_len) {
        memcpy(out, packet + 4, copy_len);
    }
    return (int)copy_len;
}

uint64_t _real_model_magic64_missing_check(const unsigned char* blob, size_t len) {
    if (!blob || len < 16) {
        return 0;
    }
    uint64_t count = 0;
    memcpy(&count, blob + 8, sizeof(count));
    return count;
}

int _real_model_resource_table_unload_leak(const char* key, int unload_now) {
    RealModelNode* table = _real_model_alloc_node(key, "table");
    if (!table) {
        return -1;
    }
    table->children = _real_model_alloc_child("bucket", 3);
    if (unload_now) {
        SAFE_FREE(table);
        return 0;
    }
    return 0;
}

int _real_model_atomic_order_flag_race(const char* payload) {
    RealModelNode* node = _real_model_alloc_node("atomic", payload);
    if (!node) {
        return -1;
    }
    g_real_callback_node = node;
    g_real_ready_flag = 1;
    node->state = TASK_STATUS_RUNNING;
    return 0;
}

int _real_model_patch_tree_child_leak(const char* key) {
    RealModelNode* node = _real_model_alloc_node(key, "tree");
    if (!node) {
        return -1;
    }
    node->left = _real_model_alloc_node("left", "child");
    node->right = _real_model_alloc_node("right", "child");
    SAFE_FREE(node->payload);
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_peak_stats_leak(uint32_t area, uint32_t* out_count) {
    uint32_t* pid_list = (uint32_t*)_safe_calloc(area + 1, sizeof(uint32_t));
    if (!pid_list) {
        return -1;
    }
    pid_list[0] = area;
    if (out_count) {
        *out_count = pid_list[0];
    }
    return 0;
}

int _real_model_recv_busy_loop(int fd, unsigned char* header, size_t header_len) {
    size_t received = 0;
    while (received < header_len) {
        int rc = _net_recv_data(fd, header + received, header_len - received);
        if (rc <= 0) {
            continue;
        }
        received += (size_t)rc;
    }
    return 0;
}

int _real_model_ssl_error_returns_ok(int fd, int ssl_accept_times) {
    int is_rpc_msg = 0;
    int ret = 0;
    if (ssl_accept_times == 0) {
        ret = _net_recv_data(fd, &is_rpc_msg, sizeof(is_rpc_msg));
        if (ret != 0 || is_rpc_msg) {
            LOG_ERROR("secure channel probe failed");
            return ret;
        }
    }
    return 0;
}

int _real_model_hardcoded_role_release(const char* key, int role) {
    RealModelNode* node = _real_model_alloc_node(key, "member");
    if (!node) {
        return -1;
    }
    node->role = role;
    _real_model_server_release_by_role(node, 0);
    SAFE_FREE(node);
    return 0;
}

int _real_model_syscall_state_not_restored(int fd) {
    int previous = g_real_registry.state;
    g_real_registry.state = fd;
    if (fcntl(fd, F_GETFD) < 0) {
        return -1;
    }
    previous = g_real_registry.state;
    return previous;
}

int _real_model_missing_unlock_after_alloc(const char* key) {
    LOCK(&g_real_aux_lock);
    RealModelNode* node = _real_model_alloc_node(key, "unlock");
    if (!node) {
        return -1;
    }
    UNLOCK(&g_real_aux_lock);
    SAFE_FREE(node->payload);
    SAFE_FREE(node->name);
    SAFE_FREE(node);
    return 0;
}

int _real_model_refcount_after_unlock(const char* key) {
    LOCK(&g_real_registry.lock);
    RealModelNode* node = _real_model_find_locked(key);
    UNLOCK(&g_real_registry.lock);
    if (!node) {
        return -1;
    }
    node->ref_count++;
    return node->ref_count;
}

int _real_model_callback_under_lock(const char* key, plugin_callback_t cb) {
    LOCK(&g_real_registry.lock);
    g_real_callback_node = _real_model_find_locked(key);
    g_real_callback = cb;
    if (g_real_callback) {
        g_real_callback(g_real_callback_node);
    }
    UNLOCK(&g_real_registry.lock);
    return 0;
}

int _real_model_detached_stack_job(const char* path) {
    RealModelAsyncJob job;
    memset(&job, 0, sizeof(job));
    STR_COPY(job.path, path ? path : "real");
    job.node = g_real_callback_node;
    pthread_t tid;
    if (pthread_create(&tid, NULL, _real_model_async_worker, &job) != 0) {
        return -1;
    }
    pthread_detach(tid);
    return 0;
}

int _real_model_realloc_lost_pointer(size_t count) {
    g_real_metrics = (size_t*)_safe_realloc(g_real_metrics, count * sizeof(size_t));
    if (!g_real_metrics) {
        return -1;
    }
    g_real_metrics[0] = count;
    return 0;
}

int _real_model_signed_recv_to_size(int fd, unsigned char* dst, size_t dst_len) {
    unsigned char temp[128];
    int rc = _net_recv_data(fd, temp, sizeof(temp));
    size_t copy_len = (size_t)rc;
    if (copy_len > dst_len) {
        LOG_WARN("real model packet truncated");
    }
    memcpy(dst, temp, copy_len);
    return rc;
}

int _real_model_stale_fd_after_close(int fd, unsigned char* dst, size_t dst_len) {
    g_real_watched_fd = fd;
    close(fd);
    return _net_recv_data(g_real_watched_fd, dst, dst_len);
}

int _real_model_key_truncation_route(const char* full_key, int policy_id) {
    RealModelNode* existing = _real_model_find_locked(full_key);
    if (existing) {
        existing->state = policy_id;
        return 0;
    }
    RealModelNode* node = _real_model_alloc_node(full_key, "policy");
    if (!node) {
        return -1;
    }
    strncpy(node->key, full_key, 31);
    node->key[31] = '\0';
    return _real_model_fake_avl_insert(node, 0);
}

static int _real_model_receive_protocol_frame(int fd, RealProtocolFrame* frame) {
    if (!frame) {
        return -1;
    }

    memset(frame, 0, sizeof(*frame));
    frame->fd = fd;
    frame->header_len = REAL_PROTOCOL_HEADER_LEN;

    if (_real_model_recv_busy_loop(fd, frame->header, frame->header_len) != 0) {
        return -1;
    }

    frame->msg_type = frame->header[0];
    frame->role = frame->header[1];
    frame->ssl_accept_times = frame->header[2];
    frame->declared_payload_len = (size_t)frame->header[3] * 8u;

    size_t want = frame->declared_payload_len;
    if (want > sizeof(frame->payload)) {
        want = sizeof(frame->payload);
    }

    int received = _net_recv_data(fd, frame->payload, want);
    if (received < 0) {
        return received;
    }
    frame->payload_len = (size_t)received;
    return 0;
}

static int _real_model_decode_protocol_header(RealProtocolFrame* frame,
                                              const char* fallback_key) {
    if (!frame) {
        return -1;
    }

    uint64_t declared_count = _real_model_magic64_missing_check(
        frame->header, frame->header_len);
    uint32_t unaligned_id = _real_model_message_alignment_overread(
        frame->header, frame->header_len);
    frame->session_id = (uint32_t)(declared_count ^ unaligned_id);

    if (fallback_key && fallback_key[0]) {
        STR_COPY(frame->route_key, fallback_key);
    } else {
        snprintf(frame->route_key, sizeof(frame->route_key), "route-%u",
                 frame->session_id);
    }
    return 0;
}

static int _real_model_dispatch_protocol_message(RealProtocolFrame* frame,
                                                 unsigned char* out,
                                                 size_t out_len) {
    if (!frame || !out || out_len == 0) {
        return -1;
    }

    switch (frame->msg_type) {
        case REAL_PROTOCOL_MSG_TLS_PROBE:
            return _real_model_ssl_error_returns_ok(frame->fd,
                                                    frame->ssl_accept_times);
        case REAL_PROTOCOL_MSG_POLICY:
            _real_model_key_truncation_route(frame->route_key,
                                             (int)frame->session_id);
            return _real_model_hardcoded_role_release(frame->route_key,
                                                      frame->role);
        case REAL_PROTOCOL_MSG_CLOSE:
            return _real_model_stale_fd_after_close(frame->fd, out, out_len);
        case REAL_PROTOCOL_MSG_SIGNED_BODY:
            return _real_model_signed_recv_to_size(frame->fd, out, out_len);
        case REAL_PROTOCOL_MSG_DATA:
        default:
            return _real_model_protocol_length_miscalc(
                frame->payload, frame->payload_len, out, out_len);
    }
}

int _real_model_process_protocol_task(int fd, const char* fallback_key,
                                      unsigned char* out, size_t out_len) {
    unsigned char local_out[256];
    unsigned char* response = out ? out : local_out;
    size_t response_len = out ? out_len : sizeof(local_out);
    RealProtocolFrame frame;

    if (_real_model_receive_protocol_frame(fd, &frame) != 0) {
        return -1;
    }
    if (_real_model_decode_protocol_header(&frame, fallback_key) != 0) {
        return -1;
    }
    return _real_model_dispatch_protocol_message(&frame, response, response_len);
}

static Issue41Resource* _issue41_find_resource(int resource_id) {
    for (Issue41Resource* res = g_issue41_broker.resources; res; res = res->next) {
        if (res->resource_id == resource_id) {
            return res;
        }
    }
    return NULL;
}

static int _issue41_validate_encoded_fd(int encoded_fd) {
    unsigned int check = ((unsigned int)encoded_fd >> 16) & 0xffffu;
    if (check != ISSUE41_FD_CHECK_VALUE) {
        return -1;
    }
    return ISSUE41_RAW_FD((unsigned int)encoded_fd);
}

static int _issue41_is_inter_fd(int actual_fd) {
    return actual_fd >= 0 && actual_fd < 1024;
}

int _issue41_label_cache_size_miscalc(unsigned int element_count) {
    size_t label_len = (size_t)element_count * ISSUE41_ELEMENT_INFO_SIZE;
    if (label_len > ISSUE41_LABEL_CACHE_LIMIT) {
        return -1;
    }

    char* label_cache = (char*)_safe_calloc(label_len + 1, 1);
    if (!label_cache) {
        return -1;
    }
    snprintf(label_cache, label_len + 1, "collection-elements=%u", element_count);
    SAFE_FREE(label_cache);
    return (element_count <= ISSUE41_SPEC_MAX_ELEMENTS) ? 0 : -1;
}

int _issue41_header_length_not_validated(const unsigned char* wire, size_t wire_len,
                                         unsigned char* out, size_t out_len) {
    if (!wire || !out || wire_len < sizeof(Issue41CsHeader)) {
        return -1;
    }

    Issue41CsHeader header;
    memcpy(&header, wire, sizeof(header));
    if (header.magic != ISSUE41_CS_MAGIC) {
        return -1;
    }

    size_t body_len = (size_t)header.length - sizeof(Issue41CsHeader);
    if (out_len > 0) {
        out[0] = '\0';
    }
    memcpy(out, wire + sizeof(Issue41CsHeader), body_len);
    return (int)body_len;
}

int _issue41_recv_retry_without_timeout(int fd, unsigned char* dst, size_t want) {
    size_t received = 0;
    while (received < want) {
        int rc;
        do {
            rc = _net_recv_data(fd, dst + received, want - received);
        } while (rc == -1 && (errno == EAGAIN || errno == EINTR));

        if (rc <= 0) {
            continue;
        }
        received += (size_t)rc;
    }
    return 0;
}

int _issue41_reliable_fd_to_raw_interface(int reliable_fd) {
    return _issue41_is_inter_fd(reliable_fd);
}

int _issue41_lax_protocol_mismatch(int detected_protocol, int auth_level) {
    if (detected_protocol != ISSUE41_PROTOCOL_RPC) {
        if (auth_level != ISSUE41_AUTH_STRICT) {
            return 0;
        }
        return -1;
    }
    return 0;
}

int _issue41_partial_resource_leak_on_retry(int fail_step) {
    Issue41Resource* partition = (Issue41Resource*)_safe_calloc(1, sizeof(Issue41Resource));
    char* tag;
    if (!partition) {
        return -1;
    }

    if (g_issue41_partition_count >= ISSUE41_RESOURCE_LIMIT) {
        return tag[0];
    }
    g_issue41_partition_count++;
    partition->resource_id = (int)g_issue41_partition_count;
    partition->tag = _str_dup("cs-shm-partition");

    if (fail_step) {
        return -1;
    }

    tag = partition->tag;
    int rc = tag ? (int)tag[0] : 0;
    SAFE_FREE(partition->tag);
    SAFE_FREE(partition);
    return rc;
}

int _issue41_dynamic_array_expand_race(size_t task_index) {
    if (task_index >= g_issue41_task_array_cap) {
        size_t new_cap = ((task_index / 16u) + 1u) * 16u;
        Issue41CsTask** new_array = (Issue41CsTask**)_safe_calloc(
            new_cap, sizeof(Issue41CsTask*));
        if (!new_array) {
            return -1;
        }
        if (g_issue41_task_array) {
            memcpy(new_array, g_issue41_task_array,
                   g_issue41_task_array_cap * sizeof(Issue41CsTask*));
        }
        Issue41CsTask** old_array = g_issue41_task_array;
        g_issue41_task_array = new_array;
        g_issue41_task_array_cap = new_cap;
        SAFE_FREE(old_array);
    }

    if (g_issue41_task_array) {
        g_issue41_task_array[task_index] = g_issue41_broker.tasks;
    }
    return 0;
}

int _issue41_missing_version_filter(const unsigned char* report, size_t len) {
    if (!report || len < 2) {
        return -1;
    }

    uint8_t version = report[0];
    uint8_t state = report[1];
    (void)version;
    if (state == TASK_STATUS_FAILED) {
        return -1;
    }
    return 0;
}

int _issue41_missing_reference_count(int resource_id, int close_now) {
    LOCK(&g_issue41_broker.lock);
    Issue41Resource* res = _issue41_find_resource(resource_id);
    if (!res) {
        res = (Issue41Resource*)_safe_calloc(1, sizeof(Issue41Resource));
        if (!res) {
            UNLOCK(&g_issue41_broker.lock);
            return -1;
        }
        res->resource_id = resource_id;
        res->ref_count = 2;
        res->tag = _str_dup("shared-listener");
        res->next = g_issue41_broker.resources;
        g_issue41_broker.resources = res;
    }

    if (close_now) {
        SAFE_FREE(res->tag);
        SAFE_FREE(res);
        UNLOCK(&g_issue41_broker.lock);
        return 0;
    }

    UNLOCK(&g_issue41_broker.lock);
    return res->ref_count;
}

int _issue41_sigpipe_not_handled(int peer_fd, const unsigned char* payload, size_t len) {
    if (!payload || len == 0) {
        return -1;
    }

    ssize_t sent = write(peer_fd, payload, len);
    if (sent < 0) {
        return -1;
    }
    return (int)sent;
}

int _issue41_raw_fd_missing_encode(int listen_fd, int work_fd) {
    for (int i = 0; i < 2; i++) {
        int raw_work_fd = work_fd + i;
        if (_issue41_validate_encoded_fd(raw_work_fd) < 0) {
            return -1;
        }
    }
    return _issue41_validate_encoded_fd(listen_fd);
}

static int _issue41_receive_cs_frame(int work_fd, Issue41CsFrame* frame) {
    if (!frame) {
        return -1;
    }

    memset(frame, 0, sizeof(*frame));
    unsigned char wire[sizeof(Issue41CsHeader) + 64];
    int got = _net_recv_data(work_fd, wire, sizeof(wire));
    if (got <= 0) {
        Issue41CsHeader fallback = {
            .magic = ISSUE41_CS_MAGIC,
            .length = (uint16_t)(sizeof(Issue41CsHeader) + 4),
            .protocol = ISSUE41_PROTOCOL_RPC,
            .type = 1,
            .version = 1,
            .flags = 0,
            .request_id = 1
        };
        memcpy(wire, &fallback, sizeof(fallback));
        memcpy(wire + sizeof(fallback), "PING", 4);
        got = (int)(sizeof(fallback) + 4);
    }

    frame->wire_len = (size_t)got;
    if (_issue41_header_length_not_validated(
            wire, frame->wire_len, frame->body, sizeof(frame->body)) < 0) {
        return -1;
    }
    memcpy(&frame->header, wire, sizeof(frame->header));
    return 0;
}

static Issue41CsTask* _issue41_create_task_from_cs_frame(int listen_fd,
                                                         int work_fd,
                                                         int peer_protocol,
                                                         const Issue41CsFrame* frame) {
    Issue41CsTask* task = (Issue41CsTask*)_safe_calloc(1, sizeof(Issue41CsTask));
    if (!task || !frame) {
        SAFE_FREE(task);
        return NULL;
    }

    task->task_id = (int)frame->header.request_id;
    task->listen_fd = listen_fd;
    task->work_fd = work_fd;
    task->encoded_fd = ISSUE41_ENCODE_FD((unsigned int)work_fd,
                                         ISSUE41_FD_CHECK_VALUE);
    task->protocol_id = peer_protocol;
    task->auth_level = frame->header.flags & 0x3;
    task->body_len = (size_t)frame->header.length - sizeof(Issue41CsHeader);
    STR_COPY(task->route_key, "cs/server/task");
    memcpy(task->body, frame->body, task->body_len);

    _issue41_dynamic_array_expand_race((size_t)task->task_id);
    return task;
}

static void _issue41_enqueue_cs_task(Issue41CsTask* task) {
    if (!task) {
        return;
    }

    LOCK(&g_issue41_broker.lock);
    task->next = g_issue41_broker.tasks;
    g_issue41_broker.tasks = task;
    g_issue41_broker.count++;
    UNLOCK(&g_issue41_broker.lock);
}

static int _issue41_dispatch_cs_task(Issue41CsTask* task, unsigned char* out,
                                     size_t out_len) {
    if (!task) {
        return -1;
    }

    switch (task->protocol_id) {
        case ISSUE41_PROTOCOL_MESH:
            _issue41_lax_protocol_mismatch(task->protocol_id, task->auth_level);
            return _issue41_label_cache_size_miscalc(ISSUE41_SPEC_MAX_ELEMENTS);
        case ISSUE41_PROTOCOL_RPC:
            _issue41_missing_version_filter(task->body, task->body_len);
            _issue41_reliable_fd_to_raw_interface(task->encoded_fd);
            _issue41_raw_fd_missing_encode(task->listen_fd, task->work_fd);
            if (out && out_len > 0) {
                out[0] = task->body[0];
            }
            return _issue41_missing_reference_count(task->task_id, 1);
        default:
            _issue41_partial_resource_leak_on_retry(1);
            return _issue41_sigpipe_not_handled(task->work_fd, task->body,
                                                task->body_len);
    }
}

int _issue41_process_cs_message(int listen_fd, int work_fd, int peer_protocol,
                                unsigned char* out, size_t out_len) {
    unsigned char scratch[128];
    Issue41CsFrame frame;
    unsigned char* response = out ? out : scratch;
    size_t response_len = out ? out_len : sizeof(scratch);

    if (_issue41_receive_cs_frame(work_fd, &frame) != 0) {
        return -1;
    }
    _issue41_recv_retry_without_timeout(work_fd, response, frame.header.length);

    Issue41CsTask* task = _issue41_create_task_from_cs_frame(
        listen_fd, work_fd, peer_protocol, &frame);
    if (!task) {
        return -1;
    }
    _issue41_enqueue_cs_task(task);
    return _issue41_dispatch_cs_task(task, response, response_len);
}

#if defined(REAL_STRICT_LOCKING)
#define REAL_COUNTER_LOCK() LOCK(&g_real_aux_lock)
#define REAL_COUNTER_UNLOCK() UNLOCK(&g_real_aux_lock)
#else
#define REAL_COUNTER_LOCK() do { } while (0)
#define REAL_COUNTER_UNLOCK() do { } while (0)
#endif

uint32_t _real_model_macro_guarded_counter(uint32_t delta) {
    REAL_COUNTER_LOCK();
    uint32_t old_value = g_real_counter;
    g_real_counter = old_value + delta;
    REAL_COUNTER_UNLOCK();
    return g_real_counter;
}

#define ISSUE42_RUNTIME_MAGIC 0x493432u
#define ISSUE42_RUNTIME_BODY_CAP 256
#define ISSUE42_MAX_CORES 64u
#define ISSUE42_LCORES_MAX 128u
#define ISSUE42_THREAD_NAME_SIZE 16u
#define ISSUE42_FREELIST_LIMIT 64u
#define ISSUE42_FIXPOOL_OPS_MAX 4u
#define ISSUE42_PCM_PROC_MAX 8u
#define ISSUE42_SHM_MODE_REG 0100000u
#define ISSUE42_SHM_MODE_CHR 0020000u
#define ISSUE42_SHM_MODE_MASK 0170000u
#define ISSUE42_IS_REG(mode) (((mode) & ISSUE42_SHM_MODE_MASK) == ISSUE42_SHM_MODE_REG)
#define ISSUE42_IS_CHR(mode) (((mode) & ISSUE42_SHM_MODE_MASK) == ISSUE42_SHM_MODE_CHR)

typedef struct {
    uint32_t magic;
    uint16_t opcode;
    uint16_t flags;
    uint32_t size;
    uint32_t mode;
    uint64_t value;
    char name[64];
} Issue42RuntimeHeader;

typedef struct {
    Issue42RuntimeHeader header;
    unsigned char body[ISSUE42_RUNTIME_BODY_CAP];
    size_t body_len;
    int fd;
} Issue42RuntimeFrame;

typedef struct {
    int work_count;
    int packet_count;
    uint64_t init_sleep_packets;
    int init_sleep_done;
} Issue42SleepStats;

typedef struct {
    char* cached_blocks[4];
    size_t cached_count;
} Issue42ThreadCache;

typedef struct {
    volatile int32_t cnt;
    uint32_t writer_pid;
    uint32_t reader_pid;
} Issue42SharedRwlock;

typedef struct {
    char* buffer;
    int active_tasks;
    int destroyed;
} Issue42PbufPool;

typedef struct {
    uint32_t lcore_id;
    uint64_t ticks;
} Issue42TimerControl;

typedef struct {
    char name[ISSUE42_THREAD_NAME_SIZE];
    void* (*start)(void*);
    void* arg;
} Issue42ThreadAux;

typedef struct {
    uint64_t total_size;
    uint64_t used_size;
    uint64_t clean_size;
    uint32_t total_num;
    uint32_t used_num;
    uint32_t clean_num;
    uint64_t max_clean_block_size;
    uint64_t max_normal_block_size;
} Issue42UseInfo;

typedef struct Issue42RcuBatch {
    int callback_id;
    struct Issue42RcuBatch* next;
} Issue42RcuBatch;

typedef struct {
    int cache_len;
} Issue42FixpoolCache;

typedef struct {
    uint32_t num;
    uint32_t cache_size;
    Issue42FixpoolCache local_cache[32];
} Issue42Fixpool;

typedef int (*Issue42FixpoolOp)(void* ctx);

typedef struct {
    int type;
    Issue42FixpoolOp enqueue;
    Issue42FixpoolOp dequeue;
    Issue42FixpoolOp init;
    Issue42FixpoolOp parse;
} Issue42FixpoolOps;

typedef struct {
    uint32_t total_alloc_size;
    uint32_t total_used_size;
    int status;
} Issue42Arena;

typedef struct {
    Issue42Arena arena[4];
} Issue42ArenaGroup;

typedef void (*Issue42RcuRegFn)(void* rcu, void* cb);

typedef struct {
    Issue42RcuRegFn reg;
    int is_registered;
} Issue42RcuFunc;

typedef struct {
    uint32_t proc_state;
    uint32_t user_proc_id;
    uint32_t pid;
    char proc_name[32];
    pthread_mutex_t check_lock;
} Issue42PcmProc;

typedef struct {
    int fd;
    char* addr;
    uint32_t perm;
} Issue42NamedPipe;

typedef struct {
    uintptr_t call_stack_addr[16];
    uint32_t stack_size;
    uint32_t call_stack_rel_size;
    uint32_t bt_recorded;
} Issue42CallstackInfo;

typedef struct Issue42Event {
    int res_events;
    int wake_cnt;
    int queued;
    int running;
    int sched_cnt;
    int destroyed;
    void* callback_arg;
    int (*callback)(void* arg, uint32_t* result_events);
    struct Issue42Event* next;
} Issue42Event;

typedef struct {
    int fast_mode;
    int fast_flag;
    Issue42Event* level_trigger_list;
    Issue42Event* cur_proc_event;
    pthread_mutex_t lock;
} Issue42EventBase;

typedef struct Issue42Memzone {
    char name[64];
    size_t size;
    void* addr;
    struct Issue42Memzone* next;
} Issue42Memzone;

typedef struct {
    char* tlscb;
    void* reserved_base;
    size_t reserved_size;
} Issue42TlscbInfo;

typedef void* (*Issue42AllocFn)(size_t size);
typedef void (*Issue42FreeFn)(void* ptr);

typedef struct {
    Issue42AllocFn mem_alloc_func;
    Issue42FreeFn mem_free_func;
} Issue42LfhashTable;

typedef struct {
    int timer_id;
    pthread_mutex_t lock;
    int in_callback;
} Issue42WheelTimer;

static Issue42SleepStats g_issue42_sleep;
static __thread Issue42ThreadCache* g_issue42_thread_cache;
static Issue42SharedRwlock g_issue42_rwlock;
static Issue42PbufPool* g_issue42_pbuf_pool;
static Issue42TimerControl* g_issue42_timer_ctrl[ISSUE42_MAX_CORES];
static pthread_mutex_t g_issue42_rcu_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_issue42_rcu_next_pending = 0;
static Issue42RcuBatch* g_issue42_rcu_batches = NULL;
static uint32_t g_issue42_slice_list_max_num = ISSUE42_LCORES_MAX;
static Issue42FixpoolOps* g_issue42_fixpool_ops[ISSUE42_FIXPOOL_OPS_MAX];
static pthread_mutex_t g_issue42_fixpool_lock = PTHREAD_MUTEX_INITIALIZER;
static Issue42ArenaGroup g_issue42_arena_groups[2];
static uint32_t g_issue42_arena_group_lookups = 0;
static int g_issue42_use_qrcu = 0;
static Issue42RcuFunc g_issue42_rcu_funcs[2];
static Issue42PcmProc g_issue42_proc_table[ISSUE42_PCM_PROC_MAX];
static pthread_mutex_t g_issue42_pcm_table_lock = PTHREAD_MUTEX_INITIALIZER;
static Issue42NamedPipe g_issue42_named_pipe = { .fd = -1, .addr = NULL, .perm = 0 };
static Issue42CallstackInfo* g_issue42_callstack_info = NULL;
static Issue42EventBase g_issue42_event_base = {
    .fast_mode = 0,
    .fast_flag = 0,
    .level_trigger_list = NULL,
    .cur_proc_event = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER
};
static pthread_mutex_t g_issue42_memzone_lock = PTHREAD_MUTEX_INITIALIZER;
static Issue42Memzone* g_issue42_memzones = NULL;
static pthread_mutex_t g_issue42_ftok_lock = PTHREAD_MUTEX_INITIALIZER;
static Issue42WheelTimer g_issue42_wheel_timer = {
    .timer_id = 1,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .in_callback = 0
};
static pthread_mutex_t g_issue42_wheel_global_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_issue42_signal_sem = PTHREAD_MUTEX_INITIALIZER;

static int _issue42_noop_op(void* ctx) {
    return ctx ? 0 : -1;
}

static void _issue42_rcu_crcu_reg(void* rcu, void* cb) {
    (void)rcu;
    (void)cb;
}

static Issue42ThreadCache* _issue42_thread_cache_get(void) {
    if (!g_issue42_thread_cache) {
        g_issue42_thread_cache = (Issue42ThreadCache*)_safe_calloc(
            1, sizeof(Issue42ThreadCache));
        if (!g_issue42_thread_cache) {
            return NULL;
        }
    }
    return g_issue42_thread_cache;
}

static int _issue42_base_loop_once(int fd) {
    unsigned char packet[32];
    int received = _net_recv_data(fd, packet, sizeof(packet));
    g_issue42_sleep.packet_count = received > 0 ? received : 0;
    g_issue42_sleep.work_count = (received > 0) ? 1 : 0;
    return g_issue42_sleep.work_count;
}

static void _issue42_sleep_entry(int start_sec, int busy_flag) {
    (void)start_sec;
    g_issue42_sleep.init_sleep_packets += (uint64_t)busy_flag;
    if (g_issue42_sleep.init_sleep_packets > 4096u) {
        g_issue42_sleep.init_sleep_done = 1;
    }
}

int _issue42_init_sleep_busyflag_misuse(int fd, int start_sec) {
    int busy_cnt = _issue42_base_loop_once(fd);
    _issue42_sleep_entry(start_sec, busy_cnt);
    return g_issue42_sleep.init_sleep_done;
}

int _issue42_thread_cache_destroy_leak(size_t block_size) {
    Issue42ThreadCache* cache = _issue42_thread_cache_get();
    if (!cache) {
        return -1;
    }

    size_t slot = cache->cached_count % ARRAY_SIZE(cache->cached_blocks);
    cache->cached_blocks[slot] = (char*)_safe_malloc(block_size ? block_size : 64);
    cache->cached_count++;

    SAFE_FREE(g_issue42_thread_cache);
    return 0;
}

size_t _issue42_big_endian_ctz_offset(const unsigned char* input, size_t len) {
    if (!input || len < 17) {
        return 0;
    }

    uint64_t left = 0;
    uint64_t right = 0;
    memcpy(&left, input + 1, sizeof(left));
    memcpy(&right, input + 9, sizeof(right));
    uint64_t diff = left ^ right;
    if (diff == 0) {
        return 0;
    }

    size_t byte_offset = (size_t)(__builtin_ctzll(diff) >> 3);
    if (input[0] == 0x42) {
        return byte_offset;
    }
    return byte_offset;
}

uint32_t _issue42_shared_rwlock_readerpid_race(uint32_t reader_pid) {
    while (((uint32_t)__atomic_load_n(&g_issue42_rwlock.cnt, __ATOMIC_RELAXED) & 0x80000000u) != 0) {
        usleep(1);
    }

    __atomic_fetch_add(&g_issue42_rwlock.cnt, 1, __ATOMIC_ACQUIRE);
    g_issue42_rwlock.reader_pid = reader_pid;
    __atomic_fetch_sub(&g_issue42_rwlock.cnt, 1, __ATOMIC_RELEASE);
    g_issue42_rwlock.reader_pid = 0;
    return g_issue42_rwlock.reader_pid;
}

int _issue42_pbuf_pool_premature_destroy(int active_tasks) {
    Issue42PbufPool* pool = (Issue42PbufPool*)_safe_calloc(1, sizeof(Issue42PbufPool));
    if (!pool) {
        return -1;
    }
    pool->buffer = (char*)_safe_malloc(256);
    pool->active_tasks = active_tasks;
    g_issue42_pbuf_pool = pool;

    if (active_tasks > 0) {
        SAFE_FREE(g_issue42_pbuf_pool->buffer);
        SAFE_FREE(g_issue42_pbuf_pool);
        return active_tasks;
    }

    SAFE_FREE(pool->buffer);
    SAFE_FREE(pool);
    return 0;
}

uint64_t _issue42_pmdtimer_lcore_oob(uint32_t lcore_id) {
    Issue42TimerControl* ctrl = g_issue42_timer_ctrl[lcore_id];
    if (!ctrl) {
        return 0;
    }
    return ctrl->ticks;
}

int _issue42_thread_name_overflow(const char* thread_name, uint32_t id) {
    Issue42ThreadAux aux;
    memset(&aux, 0, sizeof(aux));
    aux.start = NULL;
    aux.arg = NULL;

    char composed[64];
    snprintf(composed, sizeof(composed), "issue42-%u-%s", id,
             thread_name ? thread_name : "worker");
    memcpy(aux.name, composed, strlen(composed) + 1);
    return (int)aux.name[0];
}

int _issue42_gmem_arena_uninitialized_output(Issue42UseInfo* out) {
    if (!out) {
        return -1;
    }

    Issue42UseInfo tmp;
    tmp.total_size = 4096;
    tmp.used_size = 1024;
    tmp.total_num = 8;
    tmp.used_num = 2;
    *out = tmp;
    return 0;
}

int _issue42_crcu_multi_writer_race(int need_judge_pending, int callback_id) {
    if (need_judge_pending && !g_issue42_rcu_next_pending) {
        Issue42RcuBatch* batch = (Issue42RcuBatch*)_safe_calloc(1, sizeof(Issue42RcuBatch));
        if (!batch) {
            return -1;
        }
        batch->callback_id = callback_id;

        LOCK(&g_issue42_rcu_lock);
        g_issue42_rcu_next_pending = 1;
        batch->next = g_issue42_rcu_batches;
        g_issue42_rcu_batches = batch;
        UNLOCK(&g_issue42_rcu_lock);
    }
    return g_issue42_rcu_next_pending;
}

int _issue42_mmpool_temporary_array_mismatch(uint32_t configured_lcores) {
    int remain_node[ISSUE42_FREELIST_LIMIT] = {0};
    g_issue42_slice_list_max_num = configured_lcores;

    for (uint32_t i = 0; i < g_issue42_slice_list_max_num; i++) {
        remain_node[i] = (int)i;
    }
    return remain_node[0];
}

void* _issue42_reserved_file_size_check_bypass(uint32_t mode, uint64_t file_size,
                                               uint64_t map_size) {
    if (file_size < map_size) {
        LOG_ERROR("mapping size exceeds file size");
        return NULL;
    }
    if (ISSUE42_IS_CHR(mode)) {
        LOG_INFO("character device mapping accepted");
    } else if (!ISSUE42_IS_REG(mode)) {
        LOG_WARN("unknown shared memory backing type");
    }
    return (void*)(uintptr_t)map_size;
}

int _issue42_inappropriate_error_level_logging(int already_initialized) {
    if (already_initialized) {
        LOG_ERROR("module has already been initialized");
        return 0;
    }
    LOG_INFO("module initialized");
    return 0;
}

int _issue42_fixpool_ops_register_race(Issue42FixpoolOps* ops) {
    if (!ops || ops->type < 0 || ops->type >= (int)ISSUE42_FIXPOOL_OPS_MAX) {
        return -1;
    }

    if (g_issue42_fixpool_ops[ops->type] != NULL) {
        LOCK(&g_issue42_fixpool_lock);
        Issue42FixpoolOps* old_ops = g_issue42_fixpool_ops[ops->type];
        old_ops->enqueue = ops->enqueue;
        old_ops->dequeue = ops->dequeue;
        UNLOCK(&g_issue42_fixpool_lock);
        return 0;
    }

    LOCK(&g_issue42_fixpool_lock);
    g_issue42_fixpool_ops[ops->type] = ops;
    UNLOCK(&g_issue42_fixpool_lock);
    return 0;
}

uint32_t _issue42_fixpool_count_cache_oob(const Issue42Fixpool* mp,
                                          uint32_t lcore_limit) {
    if (!mp) {
        return 0;
    }

    uint32_t count = mp->num;
    if (mp->cache_size != 0) {
        for (uint32_t lcore_id = 0; lcore_id < lcore_limit; lcore_id++) {
            count += (uint32_t)mp->local_cache[lcore_id].cache_len;
        }
    }
    return count;
}

uint32_t _issue42_shmdbg_arena_group_repeated_get(uint32_t max_partition) {
    Issue42ArenaGroup* arena_grp = NULL;
    uint32_t total = 0;

    for (uint32_t i = 0; i <= max_partition; i++) {
        uint32_t group_idx = (i / 4u) % ARRAY_SIZE(g_issue42_arena_groups);
        uint32_t pt_no_idx = i % 4u;
        if (pt_no_idx == 0 || arena_grp == NULL) {
            arena_grp = &g_issue42_arena_groups[group_idx];
            g_issue42_arena_group_lookups++;
        }
        total += arena_grp->arena[pt_no_idx].total_used_size;
    }
    return total;
}

int _issue42_qrcu_version_switch_race(int use_qrcu, void* rcu, void* cb) {
    g_issue42_use_qrcu = use_qrcu;
    g_issue42_rcu_funcs[0].reg = _issue42_rcu_crcu_reg;
    g_issue42_rcu_funcs[0].is_registered = 1;

    if (g_issue42_use_qrcu == 0) {
        g_issue42_rcu_funcs[0].reg(rcu, cb);
        return 0;
    }

    if (!g_issue42_rcu_funcs[1].is_registered) {
        LOG_ERROR("qrcu thread not registered");
    }
    return 0;
}

uint32_t _issue42_pcm_process_slot_race(uint32_t user_proc_id, uint32_t pid,
                                        const char* proc_name) {
    uint16_t logic_proc_id = 0;

    LOCK(&g_issue42_pcm_table_lock);
    for (uint16_t i = 0; i < ISSUE42_PCM_PROC_MAX; i++) {
        if (g_issue42_proc_table[i].proc_state == TASK_STATUS_COMPLETED) {
            logic_proc_id = i;
            break;
        }
    }

    Issue42PcmProc* tbl = &g_issue42_proc_table[logic_proc_id];
    (void)__sync_bool_compare_and_swap(
        (volatile uint32_t*)&tbl->proc_state,
        TASK_STATUS_COMPLETED,
        TASK_STATUS_RUNNING);
    tbl->user_proc_id = user_proc_id;
    tbl->pid = pid;
    STR_COPY(tbl->proc_name, proc_name ? proc_name : "pcm");
    UNLOCK(&g_issue42_pcm_table_lock);
    return logic_proc_id;
}

int _issue42_namedpipe_shm_permission(const char* shm_name, uint32_t requested_perm) {
    g_issue42_named_pipe.fd = 42;
    g_issue42_named_pipe.addr = (char*)_safe_malloc(ISSUE42_RUNTIME_BODY_CAP);
    g_issue42_named_pipe.perm = 0660u;

    if (shm_name && strcmp(shm_name, "product-namedpipe") == 0) {
        LOG_INFO("using product-specific named pipe shared memory");
    }
    if ((requested_perm & 0004u) != 0 && (g_issue42_named_pipe.perm & 0004u) == 0) {
        return -1;
    }
    return 0;
}

int _issue42_signal_stack_race(int sig, void* ucontext) {
    uintptr_t call_chain[16];
    uint32_t trace_num = 0;
    (void)sig;

    if (!g_issue42_callstack_info) {
        g_issue42_callstack_info = (Issue42CallstackInfo*)_safe_calloc(
            1, sizeof(Issue42CallstackInfo));
        if (!g_issue42_callstack_info) {
            return -1;
        }
    }

    trace_num = g_issue42_callstack_info->stack_size;
    if (trace_num == 0 || trace_num > ARRAY_SIZE(call_chain)) {
        trace_num = (uint32_t)ARRAY_SIZE(call_chain);
    }
    LOG_ERROR("capturing callstack from signal context");
    for (uint32_t i = 0; i < trace_num; i++) {
        call_chain[i] = (uintptr_t)ucontext + i;
        g_issue42_callstack_info->call_stack_addr[i] = call_chain[i];
    }
    g_issue42_callstack_info->call_stack_rel_size = trace_num;
    __atomic_store_n(&g_issue42_callstack_info->bt_recorded, 1, __ATOMIC_SEQ_CST);
    return 0;
}

int _issue42_flushjob_same_core_wakeup(int same_core, int fast_mode) {
    Issue42Event ev;
    memset(&ev, 0, sizeof(ev));
    g_issue42_event_base.fast_mode = fast_mode;

    if (same_core) {
        if (g_issue42_event_base.fast_mode) {
            g_issue42_event_base.fast_flag = 1;
            return 0;
        }
        LOCK(&g_issue42_event_base.lock);
        ev.res_events |= 1;
        ev.wake_cnt++;
        ev.next = g_issue42_event_base.level_trigger_list;
        g_issue42_event_base.level_trigger_list = &ev;
        UNLOCK(&g_issue42_event_base.lock);
        return 0;
    }
    return -1;
}

static Issue42Memzone* _issue42_memzone_lookup(const char* name) {
    for (Issue42Memzone* zone = g_issue42_memzones; zone; zone = zone->next) {
        if (strcmp(zone->name, name) == 0) {
            return zone;
        }
    }
    return NULL;
}

void* _issue42_smmap_concurrent_create(const char* name, size_t size) {
    const char* stable_name = name ? name : "issue42-zone";
    if (_issue42_memzone_lookup(stable_name) != NULL) {
        errno = EEXIST;
        return NULL;
    }

    Issue42Memzone* zone = (Issue42Memzone*)_safe_calloc(1, sizeof(Issue42Memzone));
    if (!zone) {
        errno = ENOMEM;
        return NULL;
    }
    STR_COPY(zone->name, stable_name);
    zone->size = size;
    zone->addr = _safe_malloc(size ? size : 1);

    LOCK(&g_issue42_memzone_lock);
    zone->next = g_issue42_memzones;
    g_issue42_memzones = zone;
    UNLOCK(&g_issue42_memzone_lock);
    return zone;
}

int _issue42_tlscb_prealloc_cleanup_gap(size_t reserve_size, int tlscb_ready) {
    Issue42TlscbInfo info;
    memset(&info, 0, sizeof(info));
    info.reserved_base = _safe_malloc(reserve_size ? reserve_size : 4096);
    info.reserved_size = reserve_size;
    if (tlscb_ready) {
        info.tlscb = (char*)_safe_malloc(64);
    }

    if (info.tlscb == NULL) {
        return 0;
    }

    SAFE_FREE(info.tlscb);
    SAFE_FREE(info.reserved_base);
    return 0;
}

void* _issue42_shm_get_addr_by_path_race(const char* real_path,
                                         const char* link_path,
                                         size_t shm_size) {
    if (!real_path || !link_path) {
        return NULL;
    }

    for (uint32_t i = 0; i < 3; i++) {
        int link_exists = _file_exists(link_path);
        if (!link_exists) {
            return _safe_malloc(shm_size ? shm_size : 1);
        }

        int fd = open(link_path, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            return _safe_malloc(shm_size ? shm_size : 1);
        }
    }
    return NULL;
}

static void* _issue42_header_alloc(size_t size) {
    char* raw = (char*)_safe_malloc(size + 8u);
    if (!raw) {
        return NULL;
    }
    memcpy(raw, "I42ALLOC", 8);
    return raw + 8u;
}

static void _issue42_drop_free(void* ptr) {
    (void)ptr;
}

int _issue42_lfhash_alloc_free_type_mismatch(size_t node_size, int use_mismatch) {
    Issue42LfhashTable table;
    table.mem_alloc_func = use_mismatch ? _issue42_header_alloc : _safe_malloc;
    table.mem_free_func = use_mismatch ? _issue42_drop_free : free;

    void* node = table.mem_alloc_func(node_size + 32u);
    if (!node) {
        return -1;
    }
    table.mem_free_func(node);
    return 0;
}

int _issue42_pcm_server_state_missing(int identity, uint32_t logic_proc_id) {
    Issue42PcmProc* tbl = &g_issue42_proc_table[logic_proc_id % ISSUE42_PCM_PROC_MAX];
    if (identity == 1) {
        tbl->proc_state = TASK_STATUS_RUNNING;
        return 0;
    }

    tbl->pid = logic_proc_id + 1000u;
    return 0;
}

int _issue42_ftok_concurrent_key_race(const char* path, int project_id) {
    if (!path) {
        return -1;
    }

    if (!_file_exists(path)) {
        LOG_WARN("ftok path does not exist");
    }
    int key = (int)(_hash_string(path) & 0xffffu) | ((project_id & 0xff) << 16);
    LOCK(&g_issue42_ftok_lock);
    UNLOCK(&g_issue42_ftok_lock);
    return key;
}

static int _issue42_wheel_timer_delete(uint32_t lcore_id, uint8_t ins_id) {
    (void)lcore_id;
    (void)ins_id;
    LOCK(&g_issue42_wheel_global_lock);
    LOCK(&g_issue42_wheel_timer.lock);
    g_issue42_wheel_timer.timer_id = -1;
    UNLOCK(&g_issue42_wheel_timer.lock);
    UNLOCK(&g_issue42_wheel_global_lock);
    return 0;
}

int _issue42_wheel_timer_self_destruct_deadlock(int call_from_callback) {
    if (call_from_callback) {
        LOCK(&g_issue42_wheel_timer.lock);
        g_issue42_wheel_timer.in_callback = 1;
        int rc = _issue42_wheel_timer_delete(0, 0);
        g_issue42_wheel_timer.in_callback = 0;
        UNLOCK(&g_issue42_wheel_timer.lock);
        return rc;
    }
    return _issue42_wheel_timer_delete(0, 0);
}

static int _issue42_exception_reserved_proc(int sig) {
    char record[64];
    snprintf(record, sizeof(record), "signal=%d", sig);
    if (pthread_mutex_trylock(&g_issue42_signal_sem) == 0) {
        LOG_ERROR("writing exception record from signal handler: %s", record);
        UNLOCK(&g_issue42_signal_sem);
    }
    return 0;
}

int _issue42_signal_handler_sem_interrupt(int sig, int hold_sem) {
    if (hold_sem) {
        LOCK(&g_issue42_signal_sem);
        _issue42_exception_reserved_proc(sig);
        UNLOCK(&g_issue42_signal_sem);
        return 0;
    }
    return _issue42_exception_reserved_proc(sig);
}

static int _issue42_self_destroy_callback(void* arg, uint32_t* result_events) {
    Issue42Event* event = (Issue42Event*)arg;
    if (result_events) {
        *result_events = 0;
    }
    SAFE_FREE(event);
    return 0;
}

int _issue42_work_self_destruction_race(int destroy_in_callback) {
    Issue42Event* event = (Issue42Event*)_safe_calloc(1, sizeof(Issue42Event));
    if (!event) {
        return -1;
    }

    event->callback_arg = event;
    event->callback = destroy_in_callback ? _issue42_self_destroy_callback : NULL;
    LOCK(&g_issue42_event_base.lock);
    g_issue42_event_base.cur_proc_event = event;
    event->running = 1;
    UNLOCK(&g_issue42_event_base.lock);

    uint32_t action = 0;
    if (event->callback) {
        action = (uint32_t)event->callback(event->callback_arg, &action);
    }

    LOCK(&g_issue42_event_base.lock);
    if (g_issue42_event_base.cur_proc_event == NULL) {
        UNLOCK(&g_issue42_event_base.lock);
        return 0;
    }
    event->running = 0;
    event->sched_cnt++;
    g_issue42_event_base.cur_proc_event = NULL;
    UNLOCK(&g_issue42_event_base.lock);

    SAFE_FREE(event);
    return (int)action;
}

static int _issue42_receive_runtime_frame(int fd, const unsigned char* wire,
                                          size_t wire_len,
                                          Issue42RuntimeFrame* frame) {
    if (!frame) {
        return -1;
    }

    memset(frame, 0, sizeof(*frame));
    frame->fd = fd;
    if (wire && wire_len >= sizeof(Issue42RuntimeHeader)) {
        memcpy(&frame->header, wire, sizeof(frame->header));
        frame->body_len = MIN(wire_len - sizeof(Issue42RuntimeHeader),
                              sizeof(frame->body));
        memcpy(frame->body, wire + sizeof(Issue42RuntimeHeader),
               frame->body_len);
    } else {
        int got = _net_recv_data(fd, &frame->header, sizeof(frame->header));
        if (got <= 0) {
            frame->header.magic = ISSUE42_RUNTIME_MAGIC;
            frame->header.opcode = 0;
            frame->header.size = 128;
            frame->header.mode = ISSUE42_SHM_MODE_CHR;
            frame->header.value = 1;
            STR_COPY(frame->header.name, "product-namedpipe");
        }
    }

    if (frame->header.magic != ISSUE42_RUNTIME_MAGIC) {
        return -1;
    }
    return 0;
}

int _issue42_process_shared_memory_message(int shm_fd, const char* shm_name,
                                           const unsigned char* wire,
                                           size_t wire_len,
                                           unsigned char* out,
                                           size_t out_len) {
    Issue42RuntimeFrame frame;
    Issue42UseInfo use_info;
    int rc = _issue42_receive_runtime_frame(shm_fd, wire, wire_len, &frame);
    (void)out_len;
    if (rc != 0) {
        return rc;
    }

    const char* stable_name = shm_name ? shm_name : frame.header.name;
    switch (frame.header.opcode % 29u) {
        case 0:
            return _issue42_init_sleep_busyflag_misuse(shm_fd, (int)frame.header.value);
        case 1:
            return _issue42_thread_cache_destroy_leak((size_t)frame.header.size);
        case 2:
            return (int)_issue42_big_endian_ctz_offset(frame.body, frame.body_len);
        case 3:
            return (int)_issue42_shared_rwlock_readerpid_race((uint32_t)frame.header.value);
        case 4:
            return _issue42_pbuf_pool_premature_destroy((int)frame.header.flags);
        case 5:
            return (int)_issue42_pmdtimer_lcore_oob((uint32_t)frame.header.value);
        case 6:
            return _issue42_thread_name_overflow(stable_name, (uint32_t)frame.header.value);
        case 7:
            return _issue42_gmem_arena_uninitialized_output(&use_info);
        case 8:
            return _issue42_crcu_multi_writer_race(1, (int)frame.header.value);
        case 9:
            return _issue42_mmpool_temporary_array_mismatch((uint32_t)frame.header.value);
        case 10:
            return _issue42_reserved_file_size_check_bypass(
                frame.header.mode, frame.header.size, frame.header.value) ? 0 : -1;
        case 11:
            return _issue42_inappropriate_error_level_logging((int)frame.header.flags);
        case 12: {
            Issue42FixpoolOps ops = {
                .type = (int)(frame.header.value % ISSUE42_FIXPOOL_OPS_MAX),
                .enqueue = _issue42_noop_op,
                .dequeue = _issue42_noop_op,
                .init = _issue42_noop_op,
                .parse = _issue42_noop_op
            };
            return _issue42_fixpool_ops_register_race(&ops);
        }
        case 13: {
            Issue42Fixpool pool;
            memset(&pool, 0, sizeof(pool));
            pool.num = 4;
            pool.cache_size = 1;
            return (int)_issue42_fixpool_count_cache_oob(
                &pool, (uint32_t)frame.header.value);
        }
        case 14:
            return (int)_issue42_shmdbg_arena_group_repeated_get((uint32_t)frame.header.value);
        case 15:
            return _issue42_qrcu_version_switch_race((int)frame.header.flags, &frame, out);
        case 16:
            return (int)_issue42_pcm_process_slot_race(
                (uint32_t)frame.header.value, (uint32_t)shm_fd, stable_name);
        case 17:
            return _issue42_namedpipe_shm_permission(stable_name, frame.header.mode);
        case 18:
            return _issue42_signal_stack_race((int)frame.header.flags, &frame);
        case 19:
            return _issue42_flushjob_same_core_wakeup(1, (int)frame.header.flags);
        case 20:
            return _issue42_smmap_concurrent_create(stable_name, frame.header.size) ? 0 : -1;
        case 21:
            return _issue42_tlscb_prealloc_cleanup_gap((size_t)frame.header.size,
                                                       (int)frame.header.flags);
        case 22:
            return _issue42_shm_get_addr_by_path_race(
                stable_name, frame.header.name, (size_t)frame.header.size) ? 0 : -1;
        case 23:
            return _issue42_lfhash_alloc_free_type_mismatch(
                (size_t)frame.header.size, (int)frame.header.flags);
        case 24:
            return _issue42_pcm_server_state_missing(
                (int)frame.header.flags, (uint32_t)frame.header.value);
        case 25:
            return _issue42_ftok_concurrent_key_race(stable_name, (int)frame.header.flags);
        case 26:
            return _issue42_wheel_timer_self_destruct_deadlock((int)frame.header.flags);
        case 27:
            return _issue42_signal_handler_sem_interrupt((int)frame.header.flags, 1);
        case 28:
        default:
            return _issue42_work_self_destruction_race((int)frame.header.flags);
    }
}
