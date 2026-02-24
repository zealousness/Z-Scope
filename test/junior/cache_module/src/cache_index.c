#include "cache_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Helper functions */
static int max(int a, int b) {
    return (a > b) ? a : b;
}

static int avl_height(avl_node_t* node) {
    return node ? node->height : 0;
}

static int avl_balance_factor(avl_node_t* node) {
    return node ? avl_height(node->left) - avl_height(node->right) : 0;
}

static avl_node_t* avl_rotate_right(avl_node_t* y) {
    avl_node_t* x = y->left;
    avl_node_t* T2 = x->right;
    
    x->right = y;
    y->left = T2;
    
    y->height = max(avl_height(y->left), avl_height(y->right)) + 1;
    x->height = max(avl_height(x->left), avl_height(x->right)) + 1;
    
    return x;
}

static avl_node_t* avl_rotate_left(avl_node_t* x) {
    avl_node_t* y = x->right;
    avl_node_t* T2 = y->left;
    
    y->left = x;
    x->right = T2;
    
    x->height = max(avl_height(x->left), avl_height(x->right)) + 1;
    y->height = max(avl_height(y->left), avl_height(y->right)) + 1;
    
    return y;
}

static avl_node_t* avl_create_node(const char* key, const void* value, size_t value_size) {
    avl_node_t* node = (avl_node_t*)malloc(sizeof(avl_node_t));
    if (!node) return NULL;
    
    strncpy(node->key, key, sizeof(node->key) - 1);
    node->key[sizeof(node->key) - 1] = '\0';
    
    node->value = malloc(value_size);
    memcpy(node->value, value, value_size);
    
    node->value_size = value_size;
    node->access_count = 0;
    node->last_access = time(NULL);
    node->left = node->right = NULL;
    node->height = 1;
    
    return node;
}

avl_node_t* avl_insert(avl_node_t* root, const char* key, const void* value, size_t value_size) {
    if (!root) {
        return avl_create_node(key, value, value_size);
    }
    
    int cmp = strcmp(key, root->key);
    
    if (cmp < 0) {
        root->left = avl_insert(root->left, key, value, value_size);
    } else if (cmp > 0) {
        root->right = avl_insert(root->right, key, value, value_size);
    } else {
        // Key exists - update value
        void* new_value = malloc(value_size);
        if (new_value) {
            root->value = new_value;
            memcpy(root->value, value, value_size);
            root->value_size = value_size;
        }
        return root;
    }
    
    root->height = 1 + max(avl_height(root->left), avl_height(root->right));
    
    int balance = avl_balance_factor(root);
    
    // Left-Left
    if (balance > 1 && strcmp(key, root->left->key) < 0)
        return avl_rotate_right(root);
    
    // Right-Right
    if (balance < -1 && strcmp(key, root->right->key) > 0)
        return avl_rotate_left(root);
    
    // Left-Right
    if (balance > 1 && strcmp(key, root->left->key) > 0) {
        root->left = avl_rotate_left(root->left);
        return avl_rotate_right(root);
    }
    
    // Right-Left
    if (balance < -1 && strcmp(key, root->right->key) < 0) {
        root->right = avl_rotate_right(root->right);
        return avl_rotate_left(root);
    }
    
    return root;
}

avl_node_t* avl_find(avl_node_t* root, const char* key) {
    if (!root || !key) return NULL;
    
    int cmp = strcmp(key, root->key);
    
    if (cmp == 0) {
        root->access_count++;
        root->last_access = time(NULL);
        return root;
    } else if (cmp < 0) {
        return avl_find(root->left, key);
    } else {
        return avl_find(root->right, key);
    }
}

static avl_node_t* avl_min_value_node(avl_node_t* node) {
    avl_node_t* current = node;
    while (current->left != NULL)
        current = current->left;
    return current;
}

avl_node_t* avl_delete(avl_node_t* root, const char* key) {
    if (!root) return NULL;
    
    int cmp = strcmp(key, root->key);
    
    if (cmp < 0) {
        root->left = avl_delete(root->left, key);
    } else if (cmp > 0) {
        root->right = avl_delete(root->right, key);
    } else {
        // Node to be deleted found
        if (!root->left || !root->right) {
            avl_node_t* temp = root->left ? root->left : root->right;
            
            if (!temp) {
                temp = root;
                root = NULL;
            } else {
                *root = *temp;
            }
            
            free(temp->value);
            free(temp);
        } else {
            avl_node_t* temp = avl_min_value_node(root->right);
            
            strcpy(root->key, temp->key);
            free(root->value);
            root->value = temp->value;
            root->value_size = temp->value_size;
            root->access_count = temp->access_count;
            root->last_access = temp->last_access;
            
            root->right = avl_delete(root->right, temp->key);
        }
    }
    
    if (!root) return NULL;
    
    root->height = 1 + max(avl_height(root->left), avl_height(root->right));
    
    int balance = avl_balance_factor(root);
    
    if (balance > 1 && avl_balance_factor(root->left) >= 0)
        return avl_rotate_right(root);
    
    if (balance > 1 && avl_balance_factor(root->left) < 0) {
        root->left = avl_rotate_left(root->left);
        return avl_rotate_right(root);
    }
    
    if (balance < -1 && avl_balance_factor(root->right) <= 0)
        return avl_rotate_left(root);
    
    if (balance < -1 && avl_balance_factor(root->right) > 0) {
        root->right = avl_rotate_right(root->right);
        return avl_rotate_left(root);
    }
    
    return root;
}

void avl_destroy(avl_node_t* root) {
    if (!root) return;
    
    avl_destroy(root->left);
    avl_destroy(root->right);
    
    free(root->value);
    free(root);
}

int avl_get_all_nodes(avl_node_t* root, avl_node_t** nodes, int* count, int max_count) {
    if (!root || *count >= max_count) return 0;
    
    avl_get_all_nodes(root->left, nodes, count, max_count);
    
    if (*count < max_count) {
        nodes[*count] = root;
        (*count)++;
    }
    
    avl_get_all_nodes(root->right, nodes, count, max_count);
    
    return *count;
}
