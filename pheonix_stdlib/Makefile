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

CFLAGS_BASE := -nostdlib -fno-stack-protector -ffreestanding -I$(INC_DIR) -fPIC
LDFLAGS := -shared -fPIC

ifeq ($(BUILD),release)
	CFLAGS := $(CFLAGS_BASE) -O2 -DNDEBUG
else
	CFLAGS := $(CFLAGS_BASE) -g -O0 -DDEBUG
endif

# Sources / Objects
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
SRCS_ASM := $(filter-out $(SRC_DIR)/asm/$(ARCH)/$(OS)/psrt.S,$(wildcard $(SRC_DIR)/asm/$(ARCH)/$(OS)/*.S))
OBJS_ASM := $(patsubst $(SRC_DIR)/asm/$(ARCH)/$(OS)/%.S,$(BUILD_DIR)/asm/$(ARCH)/$(OS)/%.o,$(SRCS_ASM))
SRCS_PSRT := $(SRC_DIR)/asm/$(ARCH)/$(OS)/psrt.S

# Output
OUT_DIR := $(BIN_DIR)/$(OS)/$(ARCH)
OUT_LIB := $(OUT_DIR)/lib$(NAME).so
OUT_PSRT := $(OUT_DIR)/psrt.o

# Colors
ifeq ($(shell command -v tput >/dev/null 2>&1 && echo yes),yes)
	C_RED := $(shell tput -Txterm setaf 1)
	C_GREEN := $(shell tput -Txterm setaf 2)
	C_YELLOW := $(shell tput -Txterm setaf 3)
	C_BLUE := $(shell tput -Txterm setaf 4)
	C_MAGENTA := $(shell tput -Txterm setaf 5)
	C_CYAN := $(shell tput -Txterm setaf 6)
	C_WHITE := $(shell tput -Txterm setaf 7)
	C_RESET := $(shell tput -Txterm sgr0)
else
	C_RED := \033[31m
	C_GREEN := \033[32m
	C_YELLOW := \033[33m
	C_BLUE := \033[34m
	C_MAGENTA := \033[35m
	C_CYAN := \033[36m
	C_WHITE := \033[37m
	C_RESET := \033[0m
endif

.PHONY: all clean help build_win dirs

all: dirs $(OUT_LIB) $(OUT_PSRT)
	@printf "$(C_GREEN)Build done for Arch=$(ARCH) OS=$(OS), at $(OUT_LIB)$(C_RESET)\n"

dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(OUT_DIR)
	@mkdir -p $(BUILD_DIR)/asm $(BUILD_DIR)/asm/$(ARCH) $(BUILD_DIR)/asm/$(ARCH)/$(OS)

$(OUT_PSRT): $(SRCS_PSRT)
	@printf "$(C_YELLOW)==> Assembling $< -> $@$(C_RESET)\n"
	@$(CC) $(CFLAGS) -c $< -o $@
	@printf "$(C_GREEN)==> Assembled $@$(C_RESET)\n"

$(OUT_LIB): $(OBJS) $(OBJS_ASM)
	@printf "$(C_YELLOW)==> Linking $(OUT_LIB)$(C_RESET)\n"
	@$(CC) $(LDFLAGS) $(OBJS) $(OBJS_ASM) -o $@
	@printf "$(C_GREEN)==> Linked $(OUT_LIB)$(C_RESET)\n"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@printf "$(C_YELLOW)==> Compiling $< -> $@$(C_RESET)\n"
	@$(CC) $(CFLAGS) -c $< -o $@
	@printf "$(C_GREEN)==> Compiled $@$(C_RESET)\n"

$(BUILD_DIR)/asm/$(ARCH)/$(OS)/%.o: $(SRC_DIR)/asm/$(ARCH)/$(OS)/%.S
	@printf "$(C_YELLOW)==> Assembling $< -> $@$(C_RESET)\n"
	@$(CC) $(CFLAGS) -c $< -o $@
	@printf "$(C_GREEN)==> Assembled $@$(C_RESET)\n"

build_win:
	@printf "$(C_YELLOW) :: Building Windows DLL (MinGW)$(C_RESET)\n"
	@$(MAKE) \
		CC=x86_64-w64-mingw32-gcc \
		OS=windows \
		OUT_LIB=$(BIN_DIR)/windows/$(ARCH)/$(NAME).dll \
		LDFLAGS="-shared" \
		all
	@printf "$(C_GREEN) :: Builded Windows DLL$(C_RESET)\n"

clean:
	@printf "$(C_YELLOW)Cleaning build artifacts$(C_RESET)\n"
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@printf "$(C_GREEN)Clean Complete$(C_RESET)\n"

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