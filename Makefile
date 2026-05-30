SRC_DIR = src
BUILD_DIR = build

CC = gcc
CFLAGS = -Wall -Iinclude -g
LDFLAGS = -lssl -lcrypto

LIB_SRCS = $(filter-out $(SRC_DIR)/main.c $(SRC_DIR)/demo_custom_key.c, $(wildcard $(SRC_DIR)/*.c))
LIB_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(LIB_SRCS))

TARGET = $(BUILD_DIR)/tcrypto
TEST_TARGET = $(BUILD_DIR)/demo_custom_key

.PHONY: all clean run test

all: $(TARGET)

$(TARGET): $(LIB_OBJS) $(BUILD_DIR)/main.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_TARGET): $(LIB_OBJS) $(BUILD_DIR)/demo_custom_key.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -rf $(BUILD_DIR)