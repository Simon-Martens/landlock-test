# Makefile for building sandboxer.c

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -Wpedantic -O2 -g

# Linker flags (for Linux Landlock)
LDFLAGS = -lrt

# Source file
SRC = sandboxer.c

# Output binary
TARGET = sandboxer

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f $(TARGET)
	rm -f $(TARGET).o

.PHONY: all clean
