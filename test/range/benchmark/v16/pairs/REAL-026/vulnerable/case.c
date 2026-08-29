typedef void (*Handler)(int);

typedef struct {
    Handler handler;
    int number;
    char text[8];
} Record;

static void (*queued_routine)(void *);
static void *queued_context;

static void copy_small(char *destination, unsigned long capacity,
                       const char *source)
{
    unsigned long index = 0UL;

    if (capacity == 0UL) {
        return;
    }
    while (index + 1UL < capacity && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

static void record_value(int number)
{
    (void)number;
}

static int invoke_later(void (*routine)(void *), void *context)
{
    queued_routine = routine;
    queued_context = context;
    return 0;
}

static void dispatch_now(void)
{
    void (*routine)(void *) = queued_routine;
    void *context = queued_context;

    queued_routine = 0;
    queued_context = 0;
    if (routine != 0) {
        routine(context);
    }
}

static void apply_record(void *context)
{
    Record *record = (Record *)context;
    int number = record->number;

    if (record->text[0] != '\0') {
        number += (int)record->text[0];
    }
    record->handler(number);
}

static int prepare_record(Handler handler, int number, const char *text)
{
    Record record;

    record.handler = handler;
    record.number = number;
    copy_small(record.text, (unsigned long)sizeof(record.text), text);
    return invoke_later(apply_record, &record);
}

int main(void)
{
    int status = prepare_record(record_value, 1, "work");

    if (status == 0) {
        dispatch_now();
    }
    return status == 0 ? 0 : 1;
}
