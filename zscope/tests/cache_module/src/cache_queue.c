#include "cache_internal.h"
#include <stdlib.h>
#include <string.h>

lru_node_t* lru_create_node(const char* key) {
    lru_node_t* node = (lru_node_t*)malloc(sizeof(lru_node_t));
    if (!node) return NULL;
    
    strncpy(node->key, key, sizeof(node->key) - 1);
    node->key[sizeof(node->key) - 1] = '\0';
    node->prev = node->next = NULL;
    
    return node;
}

void lru_move_to_front(lru_node_t** head, lru_node_t** tail, lru_node_t* node) {
    if (!node || !head || !tail) return;
    
    // Already at front
    if (*head == node) return;
    
    // Remove from current position
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    
    // Update tail if needed
    if (*tail == node) *tail = node->prev;
    
    // Move to front
    node->prev = NULL;
    node->next = *head;
    
    if (*head) (*head)->prev = node;
    *head = node;
    
    if (!*tail) *tail = node;
}

lru_node_t* lru_find_node(lru_node_t* head, const char* key) {
    lru_node_t* current = head;
    
    while (current) {
        if (strcmp(current->key, key) == 0) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

char* lru_remove_lru(lru_node_t** head, lru_node_t** tail) {
    if (!head || !tail || !*tail) return NULL;
    
    lru_node_t* lru = *tail;
    
    static char removed_key[64];
    strncpy(removed_key, lru->key, sizeof(removed_key) - 1);
    removed_key[sizeof(removed_key) - 1] = '\0';
    
    // Remove from list
    if (lru->prev) {
        lru->prev->next = NULL;
        *tail = lru->prev;
    } else {
        *head = *tail = NULL;
    }
    
    free(lru);
    
    return removed_key;  // OK actually, but demonstrates the pattern
}

void lru_destroy(lru_node_t* head) {
    lru_node_t* current = head;
    
    while (current) {
        lru_node_t* next = current->next;
        free(current);
        current = next;
    }
}

// Internal helper - removes node from list
int lru_remove_node_buggy(lru_node_t** head, lru_node_t** tail, const char* key) {
    lru_node_t* node = lru_find_node(*head, key);
    
    if (!node) return -1;
    
    // Update list pointers
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    
    if (*head == node) *head = node->next;
    if (*tail == node) *tail = node->prev;
    
    return 0;
}
