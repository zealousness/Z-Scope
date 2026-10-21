#include "wiki_demo_api.h"

#include <stdlib.h>

int wiki_execute_command(const char *command) {
    if (command == NULL || command[0] == '\0') {
        return -1;
    }

    return system(command);
}
