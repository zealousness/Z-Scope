#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <stdlib.h>

// Data processor
typedef struct {
    char* data;
    size_t size;
    int processed;
} DataPacket;

DataPacket* create_packet(const char* input, size_t size);
int process_packet(DataPacket* packet);
void free_packet(DataPacket* packet);

// Batch processing
int process_batch(char** inputs, int count);

#endif // PROCESSOR_H
