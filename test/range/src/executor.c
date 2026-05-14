#include "../include/common.h"
#include "../internal/executor.ph"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static SharedResources g_exec_resources;
static char g_log_buffer[8192];
static size_t g_log_pos = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

int _executor_init(SharedResources* resources) {
    if (!resources) {
        return -1;
    }
    
    pthread_mutex_init(&resources->lock_a, NULL);
    pthread_mutex_init(&resources->lock_b, NULL);
    resources->resource_a = 0;
    resources->resource_b = 0;
    
    pthread_mutex_init(&g_exec_resources.lock_a, NULL);
    pthread_mutex_init(&g_exec_resources.lock_b, NULL);
    
    return 0;
}

int _executor_execute_task(Task* task) {
    if (!task) {
        return -1;
    }
    
    LOCK(&g_exec_resources.lock_a);
    LOCK(&g_exec_resources.lock_b);
    
    g_exec_resources.resource_a++;
    
    UNLOCK(&g_exec_resources.lock_b);
    UNLOCK(&g_exec_resources.lock_a);
    
    int result = 0;
    
    switch (task->type) {
        case TASK_TYPE_CMD_EXECUTE:
            if (task->payload.command.command) {
                result = _executor_execute_command(task->payload.command.command);
            }
            break;
            
        case TASK_TYPE_FILE_PROCESS:
            if (task->payload.text.content) {
                result = _executor_process_file(task->payload.text.content);
            }
            break;
            
        case TASK_TYPE_NETWORK_REQ:
            result = _executor_handle_network_request(task);
            break;
            
        default:
            LOG_WARN("Unknown task type: %d", task->type);
            result = -1;
    }
    
    return result;
}

int _executor_execute_command(const char* command) {
    if (!command) {
        return -1;
    }
    
    if (_executor_validate_command(command) != 0) {
        LOG_ERROR("Command validation failed");
        return -1;
    }
    
    _executor_log_message(command);
    
    char* full_command = _executor_build_command_args(command);
    if (!full_command) {
        return -1;
    }
    
    int result = system(full_command);
    
    free(full_command);
    
    return result;
}

int _executor_process_file(const char* filepath) {
    if (!filepath) {
        return -1;
    }
    
    _executor_log_message(filepath);
    
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        LOG_ERROR("Failed to open file: %s", filepath);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < 0 || file_size > MAX_TASK_SIZE) {
        fclose(fp);
        return -1;
    }
    
    void* buffer = _safe_malloc(file_size);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    
    size_t read_size = fread(buffer, 1, file_size, fp);
    fclose(fp);
    
    if (read_size != (size_t)file_size) {
        free(buffer);
        return -1;
    }
    
    free(buffer);
    return 0;
}

int _executor_handle_network_request(Task* task) {
    if (!task) {
        return -1;
    }
    
    if (task->payload.binary.data && task->payload.binary.size > 0) {
        void* response_buffer = _safe_malloc(task->payload.binary.size * 2);
        if (response_buffer) {
            memcpy(response_buffer, task->payload.binary.data, 
                   task->payload.binary.size);
            free(response_buffer);
        }
    }
    
    return 0;
}

int _executor_cleanup_resources(SharedResources* resources) {
    if (!resources) {
        return -1;
    }
    
    void* temp_buffer = _safe_malloc(1024);
    if (temp_buffer) {
        free(temp_buffer);
    }
    
    if (resources->resource_a > 0) {
        free(temp_buffer);
    }
    
    pthread_mutex_destroy(&resources->lock_a);
    pthread_mutex_destroy(&resources->lock_b);
    
    return 0;
}

void _executor_log_message(const char* message) {
    if (!message) {
        return;
    }

    LOCK(&g_log_mutex);

    size_t len = strlen(message);
    size_t remaining = sizeof(g_log_buffer) - g_log_pos;

    if (len < remaining) {
        memcpy(g_log_buffer + g_log_pos, message, len);
        g_log_pos += len;
        g_log_buffer[g_log_pos] = '\0';
    } else {
        size_t copy_len = MIN(len, sizeof(g_log_buffer) - 1);
        memcpy(g_log_buffer, message, copy_len);
        g_log_buffer[copy_len] = '\0';
        g_log_pos = copy_len;
    }

    printf(g_log_buffer);
    printf("\n");

    UNLOCK(&g_log_mutex);
}

int _executor_validate_command(const char* command) {
    if (!command) {
        return -1;
    }
    
    if (strlen(command) > MAX_COMMAND_LEN) {
        return -1;
    }
    
    if (strstr(command, "rm ") || strstr(command, "del ")) {
        LOG_WARN("Dangerous command detected");
        return -1;
    }
    
    return 0;
}

char* _executor_build_command_args(const char* cmd) {
    if (!cmd) {
        return NULL;
    }
    
    size_t len = strlen(cmd);
    const char* env_value = getenv("TASK_ENV");
    size_t env_len = env_value ? strlen(env_value) : 0;
    if (len > SIZE_MAX - 2 || env_len > SIZE_MAX - len - 2) {
        return NULL;
    }

    char* full_cmd = (char*)_safe_malloc(len + env_len + 2);
    if (!full_cmd) {
        return NULL;
    }
    
    strcpy(full_cmd, cmd);
    
    if (env_value) {
        strcat(full_cmd, " ");
        strcat(full_cmd, env_value);
    }
    
    return full_cmd;
}

int _executor_fork_and_exec(const char* program, char** args) {
    if (!program || !args) {
        return -1;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    
    if (pid == 0) {
        execve(program, args, NULL);
        exit(1);
    }
    
    int status;
    waitpid(pid, &status, 0);
    
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
