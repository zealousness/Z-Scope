#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Helper function that allocates memory but doesn't free it
 * This is a memory leak!
 */
char* create_buffer(size_t size) {
    char* buffer = (char*)malloc(size);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, size);
    return buffer;
}

/**
 * Function with potential buffer overflow
 */
void copy_data(char* dest, const char* src, size_t dest_size) {
    // DEFECT: No bounds checking! Could overflow dest
    strcpy(dest, src);
}

/**
 * Function with resource leak (file descriptor not closed)
 */
int process_file(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }
    
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        // DEFECT: File not closed on error path!
        return -1;
    }
    
    printf("Read: %s\n", buffer);
    fclose(fp);
    return 0;
}

/**
 * Function with use-after-free vulnerability
 */
void use_after_free_example() {
    char* data = create_buffer(100);
    strcpy(data, "Hello, World!");
    printf("%s\n", data);
    
    free(data);
    
    // DEFECT: Use after free!
    printf("Still accessing: %s\n", data);
}

/**
 * Main function that demonstrates various defects
 */
int process_data_packet(const char* input) {
    // DEFECT: create_buffer allocates memory that's never freed
    char* buffer1 = create_buffer(1024);
    if (buffer1 == NULL) {
        return -1;
    }
    
    // DEFECT: Potential buffer overflow
    char small_buffer[32];
    copy_data(small_buffer, input, sizeof(small_buffer));
    
    // Some processing
    printf("Processing: %s\n", small_buffer);
    
    // DEFECT: buffer1 is never freed - memory leak!
    return 0;
}

int main(int argc, char** argv) {
    const char* test_input = "This is a very long input string that could potentially cause a buffer overflow if not handled carefully";
    
    int result = process_data_packet(test_input);
    printf("Result: %d\n", result);
    
    // Demonstrate file handling issue
    process_file("test.txt");
    
    // Demonstrate use-after-free
    use_after_free_example();
    
    return 0;
}
