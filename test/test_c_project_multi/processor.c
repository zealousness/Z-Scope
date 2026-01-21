#include "processor.h"
#include "memory.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

/**
 * Create a data packet
 */
DataPacket* create_packet(const char* input, size_t size) {
    DataPacket* packet = (DataPacket*)safe_malloc(sizeof(DataPacket));
    if (!packet) {
        return NULL;
    }
    
    packet->data = create_buffer(size + 1);  // +1 for null terminator
    if (!packet->data) {
        free(packet);
        return NULL;
    }
    
    strcpy(packet->data, input);  // Buffer overflow risk
    
    packet->size = size;
    packet->processed = 0;
    
    return packet;
}

/**
 * Process a packet
 */
int process_packet(DataPacket* packet) {
    if (!packet || !packet->data) {
        return -1;
    }
    
    // Simple processing: uppercase conversion
    for (size_t i = 0; i < packet->size; i++) {
        if (packet->data[i] >= 'a' && packet->data[i] <= 'z') {
            packet->data[i] = packet->data[i] - 32;
        }
    }
    
    packet->processed = 1;
    
    printf("Processed packet: %s\n", packet->data);
    return 0;
}

/**
 * Free a packet
 */
void free_packet(DataPacket* packet) {
    if (packet) {
        if (packet->data) {
            free(packet->data);
        }
        free(packet);
    }
}

/**
 * Process multiple packets
 */
int process_batch(char** inputs, int count) {
    if (!inputs || count <= 0) {
        return -1;
    }
    
    DataPacket** packets = (DataPacket**)malloc(count * sizeof(DataPacket*));
    if (!packets) {
        return -1;
    }
    
    // Create all packets
    for (int i = 0; i < count; i++) {
        packets[i] = create_packet(inputs[i], strlen(inputs[i]));
        if (!packets[i]) {
            free(packets);
            return -1;
        }
    }
    
    // Process all packets
    for (int i = 0; i < count; i++) {
        if (process_packet(packets[i]) != 0) {
            free(packets);
            return -1;
        }
    }
    
    // Clean up
    for (int i = 0; i < count; i++) {
        free_packet(packets[i]);
    }
    free(packets);
    
    return 0;
}
