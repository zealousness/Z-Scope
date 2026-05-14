CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpthread

INCLUDE_DIR = include
INTERNAL_DIR = internal
SRC_DIR = src
BUILD_DIR = build
TARGET = $(BUILD_DIR)/task_dispatcher

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/utils.c \
       $(SRC_DIR)/network.c \
       $(SRC_DIR)/parser.c \
       $(SRC_DIR)/plugin.c \
       $(SRC_DIR)/executor.c \
       $(SRC_DIR)/lifecycle.c

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

INCLUDES = -I$(INCLUDE_DIR) -I$(INTERNAL_DIR)

.PHONY: all clean directories

all: directories $(TARGET)

directories:
	@mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

run: all
	./$(TARGET)

test: all
	./$(TARGET) "ls -la"
	./$(TARGET) "echo 'Test command'"

.PHONY: all clean directories run test
