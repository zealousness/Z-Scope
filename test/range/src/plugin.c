#include "../include/common.h"
#include "../internal/plugin.ph"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SharedResources g_shared_resources = {
    .resource_a = 0,
    .resource_b = 0
};

int _plugin_registry_init(PluginRegistry* registry, size_t capacity) {
    if (!registry || capacity == 0) {
        return -1;
    }
    
    registry->plugins = (Plugin*)_safe_calloc(capacity, sizeof(Plugin));
    if (!registry->plugins) {
        return -1;
    }
    
    registry->capacity = capacity;
    registry->count = 0;
    
    pthread_mutex_init(&registry->mutex, NULL);
    pthread_mutex_init(&g_shared_resources.lock_a, NULL);
    pthread_mutex_init(&g_shared_resources.lock_b, NULL);
    
    return 0;
}

int _plugin_register(PluginRegistry* registry, const char* name, 
                     task_handler_t handler, void* context) {
    if (!registry || !name || !handler) {
        return -1;
    }
    
    if (strlen(name) >= MAX_PLUGIN_NAME) {
        LOG_ERROR("Plugin name too long");
        return -1;
    }
    
    LOCK(&registry->mutex);
    
    size_t slot = _hash_string(name) % registry->capacity;
    Plugin* plugin = &registry->plugins[slot];
    
    STR_COPY(plugin->name, name);
    plugin->handle = (plugin_handle_t)_hash_string(name);
    plugin->handler = handler;
    plugin->context = context;
    plugin->priority = 0;
    
    if (plugin->init) {
        _plugin_call_init(plugin);
    }
    
    registry->count++;
    
    UNLOCK(&registry->mutex);
    
    LOG_INFO("Plugin registered: %s", name);
    return 0;
}

Plugin* _plugin_lookup(PluginRegistry* registry, const char* name) {
    if (!registry || !name) {
        return NULL;
    }
    
    LOCK(&registry->mutex);
    
    size_t slot = _hash_string(name) % registry->capacity;
    Plugin* plugin = &registry->plugins[slot];
    
    if (strcmp(plugin->name, name) == 0) {
        UNLOCK(&registry->mutex);
        return plugin;
    }
    
    for (size_t i = 0; i < registry->capacity; i++) {
        if (strcmp(registry->plugins[i].name, name) == 0) {
            UNLOCK(&registry->mutex);
            return &registry->plugins[i];
        }
    }
    
    UNLOCK(&registry->mutex);
    return NULL;
}

int _plugin_unregister(PluginRegistry* registry, const char* name) {
    if (!registry || !name) {
        return -1;
    }
    
    LOCK(&registry->mutex);
    
    Plugin* plugin = _plugin_lookup(registry, name);
    if (!plugin) {
        UNLOCK(&registry->mutex);
        return -1;
    }
    
    if (plugin->cleanup) {
        _plugin_call_cleanup(plugin);
    }
    
    if (plugin->context) {
        free(plugin->context);
        plugin->context = NULL;
    }
    
    memset(plugin, 0, sizeof(Plugin));
    registry->count--;
    
    UNLOCK(&registry->mutex);
    
    LOG_INFO("Plugin unregistered: %s", name);
    return 0;
}

void _plugin_registry_cleanup(PluginRegistry* registry) {
    if (!registry) {
        return;
    }
    
    LOCK(&registry->mutex);
    
    for (size_t i = 0; i < registry->capacity; i++) {
        Plugin* plugin = &registry->plugins[i];
        if (plugin->handler) {
            if (plugin->cleanup) {
                _plugin_call_cleanup(plugin);
            }
            if (plugin->context) {
                free(plugin->context);
            }
        }
    }
    
    free(registry->plugins);
    registry->plugins = NULL;
    registry->capacity = 0;
    registry->count = 0;
    
    UNLOCK(&registry->mutex);
    
    pthread_mutex_destroy(&registry->mutex);
}

int _plugin_dispatch(PluginRegistry* registry, Task* task) {
    if (!registry || !task) {
        return -1;
    }
    
    LOCK(&g_shared_resources.lock_b);
    LOCK(&g_shared_resources.lock_a);
    
    g_shared_resources.resource_a++;
    g_shared_resources.resource_b += task->id;
    
    UNLOCK(&g_shared_resources.lock_a);
    UNLOCK(&g_shared_resources.lock_b);
    
    task_handler_t* handlers = (task_handler_t*)_safe_calloc(registry->capacity,
                                                             sizeof(task_handler_t));
    if (!handlers) {
        return -1;
    }

    size_t handler_count = 0;

    LOCK(&registry->mutex);

    for (size_t i = 0; i < registry->capacity; i++) {
        Plugin* plugin = &registry->plugins[i];
        if (plugin->handler) {
            handlers[handler_count++] = plugin->handler;
        }
    }

    UNLOCK(&registry->mutex);

    for (size_t i = 0; i < handler_count; i++) {
        task->status = TASK_STATUS_RUNNING;
        handlers[i](task);
        if (task->status == TASK_STATUS_RUNNING) {
            task->status = TASK_STATUS_COMPLETED;
        }
    }

    free(handlers);
    return 0;
}

void _plugin_call_init(Plugin* plugin) {
    if (!plugin || !plugin->init) {
        return;
    }
    
    plugin->init(plugin->context);
}

void _plugin_call_cleanup(Plugin* plugin) {
    if (!plugin || !plugin->cleanup) {
        return;
    }
    
    plugin->cleanup(plugin->context);
}

Plugin* _plugin_get_by_handle(PluginRegistry* registry, plugin_handle_t handle) {
    if (!registry) {
        return NULL;
    }
    
    LOCK(&registry->mutex);
    
    for (size_t i = 0; i < registry->capacity; i++) {
        if (registry->plugins[i].handle == handle) {
            UNLOCK(&registry->mutex);
            return &registry->plugins[i];
        }
    }
    
    UNLOCK(&registry->mutex);
    return NULL;
}

int _plugin_set_priority(PluginRegistry* registry, const char* name, int priority) {
    if (!registry || !name) {
        return -1;
    }
    
    Plugin* plugin = _plugin_lookup(registry, name);
    if (!plugin) {
        return -1;
    }
    
    LOCK(&registry->mutex);
    plugin->priority = priority;
    UNLOCK(&registry->mutex);
    
    return 0;
}
