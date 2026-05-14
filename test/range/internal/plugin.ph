#ifndef PLUGIN_PH
#define PLUGIN_PH

#include "../internal/types.ph"

int _plugin_registry_init(PluginRegistry* registry, size_t capacity);
int _plugin_register(PluginRegistry* registry, const char* name, task_handler_t handler, void* context);
Plugin* _plugin_lookup(PluginRegistry* registry, const char* name);
int _plugin_unregister(PluginRegistry* registry, const char* name);
void _plugin_registry_cleanup(PluginRegistry* registry);
int _plugin_dispatch(PluginRegistry* registry, Task* task);
void _plugin_call_init(Plugin* plugin);
void _plugin_call_cleanup(Plugin* plugin);

#endif
