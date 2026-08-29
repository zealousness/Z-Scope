typedef struct PeerSessionResource PeerSessionResource;

struct PeerSessionResource {
    int resource_id;
    int ref_count;
    char *tag;
    PeerSessionResource *next;
};

typedef struct {
    PeerSessionResource *head;
    int lock_depth;
} Broker;

static Broker broker;
static PeerSessionResource resource_storage;
static char string_storage[8];
static int resource_allocated;
static int string_allocated;

static void enter_guard(Broker *value)
{
    value->lock_depth += 1;
}

static void leave_guard(Broker *value)
{
    value->lock_depth -= 1;
}

static PeerSessionResource *allocate_resource(void)
{
    if (resource_allocated != 0) {
        return 0;
    }
    resource_allocated = 1;
    resource_storage.resource_id = 0;
    resource_storage.ref_count = 0;
    resource_storage.tag = 0;
    resource_storage.next = 0;
    return &resource_storage;
}

static char *allocate_string(const char *source)
{
    int index = 0;

    if (string_allocated != 0) {
        return 0;
    }
    while (source[index] != '\0' && index < 7) {
        string_storage[index] = source[index];
        index += 1;
    }
    string_storage[index] = '\0';
    string_allocated = 1;
    return string_storage;
}

static void release_storage(void *storage)
{
    if (storage == (void *)string_storage) {
        string_allocated = 0;
    } else if (storage == (void *)&resource_storage) {
        resource_allocated = 0;
    }
}

static PeerSessionResource *find_resource(int resource_id)
{
    PeerSessionResource *current = broker.head;

    while (current != 0) {
        if (current->resource_id == resource_id) {
            return current;
        }
        current = current->next;
    }
    return 0;
}

static void unlink_resource(PeerSessionResource *resource)
{
    PeerSessionResource **cursor = &broker.head;

    while (*cursor != 0) {
        if (*cursor == resource) {
            *cursor = resource->next;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

int publish_record(int resource_id, int close_now)
{
    PeerSessionResource *resource;

    enter_guard(&broker);
    resource = find_resource(resource_id);
    if (resource == 0) {
        resource = allocate_resource();
        if (resource == 0) {
            leave_guard(&broker);
            return -1;
        }
        resource->tag = allocate_string("local");
        if (resource->tag == 0) {
            release_storage(resource);
            leave_guard(&broker);
            return -1;
        }
        resource->resource_id = resource_id;
        resource->ref_count = 2;
        resource->next = broker.head;
        broker.head = resource;
    }
    if (close_now != 0) {
        resource->ref_count -= 1;
        if (resource->ref_count == 0) {
            unlink_resource(resource);
            release_storage(resource->tag);
            release_storage(resource);
        }
    }
    leave_guard(&broker);
    return 0;
}

static int dispatch_rpc(int resource_id, int close_now)
{
    return publish_record(resource_id, close_now);
}

int main(void)
{
    int result;

    if (broker.head != 0 || resource_allocated != 0 || string_allocated != 0) {
        return 3;
    }
    result = dispatch_rpc(7, 1);
    if (result != 0 || broker.lock_depth != 0) {
        return 4;
    }
    if (resource_allocated == 0 && string_allocated == 0 &&
        broker.head == &resource_storage) {
        return 1;
    }
    if (resource_allocated != 0 && string_allocated != 0 &&
        broker.head == &resource_storage && resource_storage.ref_count == 1) {
        return 0;
    }
    return 2;
}
