# PStdLib Makefile

NAME := pstdlib
SRC_DIR := src
INC_DIR := inc
BUILD_DIR := build
BIN_DIR := bin

# Detect OS & ARCH
OS := $(shell uname -s | tr A-Z a-z)
ARCH := $(shell uname -m)

# Default build type
BUILD ?= debug

# Compiler
CC := gcc

CFLAGS_BASE := -fPIC -I$(INC_DIR)
LDFLAGS := -shared

ifeq ($(BUILD),release)
	CFLAGS := $(CFLAGS_BASE) -O2 -DNDEBUG
else
	CFLAGS := $(CFLAGS_BASE) -g -O0 -DDEBUG
endif

# Sources / Objects
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Output
OUT_DIR := $(BIN_DIR)/$(OS)/$(ARCH)
OUT_LIB := $(OUT_DIR)/lib$(NAME).so

.PHONY: all clean help build_win dirs

all: dirs $(OUT_LIB)

dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(OUT_DIR)

$(OUT_LIB): $(OBJS)
	@echo "Linking $(OUT_LIB)..."
	@$(CC) $(LDFLAGS) $(OBJS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $< -> $@"
	@$(CC) $(CFLAGS) -c $< -o $@

build_win:
	@echo "Building Windows DLL (MinGW)..."
	@$(MAKE) \
		CC=x86_64-w64-mingw32-gcc \
		OS=windows \
		OUT_LIB=$(BIN_DIR)/windows/$(ARCH)/$(NAME).dll \
		LDFLAGS="-shared" \
		all

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)

help:
	@echo ""
	@echo "Usage:"
	@echo "  make [target] [BUILD=debug|release]"
	@echo ""
	@echo "Targets:"
	@echo "  all         Build shared library (default)"
	@echo "  build_win   Build Windows DLL using MinGW"
	@echo "  clean       Remove build and bin directories"
	@echo "  help        Show this help message"
	@echo ""
	@echo "Build types:"
	@echo "  BUILD=debug    Debug symbols, no optimizations (default)"
	@echo "  BUILD=release  Optimized, no debug symbols"
	@echo ""

