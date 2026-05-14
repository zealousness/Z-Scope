#include "../include/common.h"
#include "../internal/parser.ph"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

static TaskConfig g_default_config = {
    .queue_size = DEFAULT_QUEUE_SIZE,
    .thread_count = DEFAULT_THREAD_COUNT,
    .max_tasks_per_client = 100,
    .network = {
        .timeout_ms = 5000,
        .max_retries = 3,
        .compression_enabled = 0,
        .encryption_enabled = 0
    },
    .security = {
        .allowed_uid = 0,
        .allowed_gid = 0,
        .require_root = 0,
        .sandbox_enabled = 1
    }
};

Task* _parse_task_buffer(const void* data, size_t len) {
    if (!data || len < sizeof(TaskHeader)) {
        LOG_ERROR("Invalid task buffer");
        return NULL;
    }
    
    TaskHeader* header = (TaskHeader*)data;
    
    if (_validate_task_header(header) != 0) {
        LOG_ERROR("Invalid task header");
        return NULL;
    }
    
    Task* task = (Task*)_safe_calloc(1, sizeof(Task));
    if (!task) {
        return NULL;
    }
    
    task->type = (task_type_t)header->task_type;
    task->flags.is_urgent = (header->flags & 0x01) != 0;
    task->flags.is_async = (header->flags & 0x02) != 0;
    task->flags.requires_auth = (header->flags & 0x04) != 0;
    task->created_at = _get_timestamp_ms();
    
    const char* payload_data = (const char*)data + sizeof(TaskHeader);
    size_t payload_len = header->payload_length;
    
    if (task->type == TASK_TYPE_CMD_EXECUTE) {
        char command[4096];
        memcpy(command, payload_data, MIN(payload_len, sizeof(command) - 1));
        command[MIN(payload_len, sizeof(command) - 1)] = '\0';
        
        task->payload.command.command = _str_dup(command);
        if (!task->payload.command.command) {
            free(task);
            return NULL;
        }
        
        char* args[32];
        int arg_count = _parse_arguments(command, args, 32);
        
        task->payload.command.args = (char**)_safe_calloc(arg_count + 1, sizeof(char*));
        if (task->payload.command.args) {
            for (int i = 0; i < arg_count; i++) {
                task->payload.command.args[i] = _str_dup(args[i]);
                if (!task->payload.command.args[i]) {
                    for (int j = 0; j < i; j++) {
                        SAFE_FREE(task->payload.command.args[j]);
                    }
                    SAFE_FREE(task->payload.command.args);
                    SAFE_FREE(task->payload.command.command);
                    SAFE_FREE(task);
                    return NULL;
                }
            }
            task->payload.command.arg_count = arg_count;
        }
    } else if (task->type == TASK_TYPE_FILE_PROCESS) {
        char filepath[MAX_PATH_LEN];
        memcpy(filepath, payload_data, MIN(payload_len, sizeof(filepath) - 1));
        filepath[MIN(payload_len, sizeof(filepath) - 1)] = '\0';
        
        task->payload.text.content = _str_dup(filepath);
        task->payload.text.length = strlen(filepath);
    } else {
        void* binary_data = _safe_malloc(payload_len);
        if (binary_data) {
            memcpy(binary_data, payload_data, payload_len);
            task->payload.binary.data = binary_data;
            task->payload.binary.size = payload_len;
        }
    }
    
    return task;
}

int _parse_config_string(const char* config_str, TaskConfig* config) {
    if (!config_str || !config) {
        return -1;
    }
    
    memcpy(config, &g_default_config, sizeof(TaskConfig));
    
    char* str = _str_dup(config_str);
    if (!str) {
        return -1;
    }
    
    char* token = strtok(str, ",{}:\" ");
    while (token != NULL) {
        if (strcmp(token, "queue_size") == 0) {
            token = strtok(NULL, ",{}:\" ");
            if (token) {
                config->queue_size = atoi(token);
            }
        } else if (strcmp(token, "thread_count") == 0) {
            token = strtok(NULL, ",{}:\" ");
            if (token) {
                config->thread_count = atoi(token);
            }
        } else if (strcmp(token, "max_tasks_per_client") == 0) {
            token = strtok(NULL, ",{}:\" ");
            if (token) {
                config->max_tasks_per_client = atoi(token);
            }
        } else if (strcmp(token, "timeout_ms") == 0) {
            token = strtok(NULL, ",{}:\" ");
            if (token) {
                config->network.timeout_ms = atoi(token);
            }
        } else if (strcmp(token, "sandbox_enabled") == 0) {
            token = strtok(NULL, ",{}:\" ");
            if (token) {
                config->security.sandbox_enabled = (strcmp(token, "true") == 0);
            }
        }
        token = strtok(NULL, ",{}:\" ");
    }
    
    free(str);
    return 0;
}

int _validate_task_header(const TaskHeader* header) {
    if (!header) {
        return -1;
    }
    
    if (memcmp(header->magic, "TASK", 4) != 0) {
        return -1;
    }
    
    if (header->version != 1) {
        return -1;
    }
    
    if (header->task_type > TASK_TYPE_CUSTOM) {
        return -1;
    }
    
    if (header->payload_length > MAX_TASK_SIZE) {
        return -1;
    }
    
    return 0;
}

int _extract_payload(const void* data, size_t len, TaskHeader* header, void** payload) {
    if (!data || !header || !payload) {
        return -1;
    }
    
    if (len < sizeof(TaskHeader)) {
        return -1;
    }
    
    memcpy(header, data, sizeof(TaskHeader));
    
    if (_validate_task_header(header) != 0) {
        return -1;
    }
    
    if (header->payload_length > len - sizeof(TaskHeader)) {
        return -1;
    }
    
    *payload = _safe_malloc(header->payload_length);
    if (!*payload) {
        return -1;
    }
    
    memcpy(*payload, (const char*)data + sizeof(TaskHeader), header->payload_length);
    
    return 0;
}

int _serialize_task(const Task* task, void** buffer, size_t* len) {
    if (!task || !buffer || !len) {
        return -1;
    }
    
    size_t payload_len = 0;
    void* payload_data = NULL;
    
    if (task->type == TASK_TYPE_CMD_EXECUTE && task->payload.command.command) {
        payload_len = strlen(task->payload.command.command) + 1;
        payload_data = task->payload.command.command;
    } else if (task->type == TASK_TYPE_FILE_PROCESS && task->payload.text.content) {
        payload_len = task->payload.text.length;
        payload_data = task->payload.text.content;
    } else if (task->payload.binary.data) {
        payload_len = task->payload.binary.size;
        payload_data = task->payload.binary.data;
    }
    
    size_t total_len = sizeof(TaskHeader) + payload_len;
    *buffer = _safe_malloc(total_len);
    if (!*buffer) {
        return -1;
    }
    
    TaskHeader* header = (TaskHeader*)*buffer;
    memcpy(header->magic, "TASK", 4);
    header->version = 1;
    header->task_type = task->type;
    header->flags = (task->flags.is_urgent ? 0x01 : 0) |
                    (task->flags.is_async ? 0x02 : 0) |
                    (task->flags.requires_auth ? 0x04 : 0);
    header->payload_length = (uint32_t)payload_len;
    header->checksum = 0;
    
    if (payload_data && payload_len > 0) {
        memcpy((char*)*buffer + sizeof(TaskHeader), payload_data, payload_len);
    }
    
    *len = total_len;
    return 0;
}

int _validate_task_config(const TaskConfig* cfg) {
    if (!cfg) {
        return -1;
    }
    
    if (cfg->queue_size == 0 || cfg->queue_size > 65536) {
        return -1;
    }
    
    if (cfg->thread_count == 0 || cfg->thread_count > 256) {
        return -1;
    }
    
    return 0;
}

char* _parse_command_string(const char* input) {
    if (!input) {
        return NULL;
    }
    
    char* cmd = _str_dup(input);
    if (!cmd) {
        return NULL;
    }
    
    char* p = cmd;
    while (*p) {
        if (isspace(*p)) {
            *p = '\0';
            break;
        }
        p++;
    }
    
    return cmd;
}

int _parse_arguments(char* cmd, char** args, int max_args) {
    if (!cmd || !args || max_args <= 0) {
        return 0;
    }

    int count = 0;
    char* p = cmd;

    while (*p && count < max_args) {
        while (*p && isspace((unsigned char)*p)) {
            *p++ = '\0';
        }
        if (!*p) {
            break;
        }

        args[count++] = p;
        while (*p && !isspace((unsigned char)*p)) {
            p++;
        }
    }

    return count;
}

void* _allocate_buffer(size_t size) {
    size_t total_size = size * 2;
    if (total_size < size) {
        LOG_ERROR("Integer overflow in buffer allocation");
        return NULL;
    }
    
    void* buffer = _safe_malloc(total_size);
    if (!buffer) {
        LOG_ERROR("Failed to allocate buffer");
        return NULL;
    }
    
    return buffer;
}

int _validate_task(Task* task) {
    if (!task) {
        return -1;
    }
    
    if (task->type == TASK_TYPE_CMD_EXECUTE) {
        if (!task->payload.command.command) {
            return -1;
        }
        
        char* cmd = task->payload.command.command;
        if (strlen(cmd) > MAX_COMMAND_LEN) {
            return -1;
        }
        
        if (strstr(cmd, ";") || strstr(cmd, "|") || strstr(cmd, "&")) {
            LOG_WARN("Potentially dangerous command detected");
            return -1;
        }
    } else if (task->type == TASK_TYPE_FILE_PROCESS) {
        if (!task->payload.text.content) {
            return -1;
        }
        
        char* path = task->payload.text.content;
        if (strstr(path, "..") != NULL) {
            LOG_WARN("Path traversal attempt detected");
            return -1;
        }
        
        if (_check_file_permission(path, R_OK) != 0) {
            LOG_ERROR("File permission check failed");
            return -1;
        }
        
        FILE* fp = fopen(path, "r");
        if (fp) {
            fclose(fp);
        }
    }
    
    return 0;
}
