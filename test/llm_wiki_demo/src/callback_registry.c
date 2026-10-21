#include "wiki_demo_api.h"

#include <pthread.h>
#include <string.h>

struct callback_slot {
    char name[32];
    void (*callback)(void);
};

static struct callback_slot slots[8];
static size_t slot_count;
static pthread_mutex_t slots_mutex = PTHREAD_MUTEX_INITIALIZER;

int wiki_register_callback(const char *name, void (*callback)(void)) {
    int result = -1;

    if (name == NULL || callback == NULL) {
        return -1;
    }

    pthread_mutex_lock(&slots_mutex);
    if (slot_count < sizeof(slots) / sizeof(slots[0]) && strlen(name) < sizeof(slots[0].name)) {
        strcpy(slots[slot_count].name, name);
        slots[slot_count].callback = callback;
        slot_count++;
        result = 0;
    }
    pthread_mutex_unlock(&slots_mutex);
    return result;
}
