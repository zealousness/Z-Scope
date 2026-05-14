#ifndef PARSER_PH
#define PARSER_PH

#include "../internal/types.ph"

Task* _parse_task_buffer(const void* data, size_t len);
int _parse_config_string(const char* config_str, TaskConfig* config);
int _validate_task_header(const TaskHeader* header);
int _extract_payload(const void* data, size_t len, TaskHeader* header, void** payload);
int _serialize_task(const Task* task, void** buffer, size_t* len);
int _validate_task_config(const TaskConfig* cfg);
int _validate_task(Task* task);
char* _parse_command_string(const char* input);
int _parse_arguments(char* cmd, char** args, int max_args);

#endif
