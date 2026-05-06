# PStdLib tests Makefile

SRC_DIR := src
INC_DIR := ../inc
BUILD_DIR := build
BIN_DIR := bin

# Detect OS & ARCH
OS := $(shell uname -s | tr A-Z a-z)
ARCH := $(shell uname -m)

# dir
LINK_DIR := ../bin/$(OS)/$(ARCH)
PSRT_O := ../bin/$(OS)/$(ARCH)/psrt.o

# Default build type
BUILD ?= debug

# Compiler
CC := gcc

CFLAGS_BASE := -nostdlib -fno-stack-protector -ffreestanding -I$(INC_DIR)
LDFLAGS := -L$(LINK_DIR) -lpstdlib

ifeq ($(BUILD),release)
	CFLAGS := $(CFLAGS_BASE) -O2 -DNDEBUG
else
	CFLAGS := $(CFLAGS_BASE) -g -O0 -DDEBUG
endif

# Output
OUT_DIR := $(BIN_DIR)/$(OS)/$(ARCH)
OUT_PREFIX := 

# Sources / Objects
SRCS := $(wildcard $(SRC_DIR)/*.c)
OUTS := $(patsubst $(SRC_DIR)/%.c,$(OUT_DIR)/%$(OUT_PREFIX),$(SRCS))

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

all: dirs $(OUTS)
	@printf "$(C_GREEN)Build done for Arch=$(ARCH) OS=$(OS)\nFiles: $(OUTS)$(C_RESET)\n"

dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(OUT_DIR)

$(OUT_DIR)/%$(OUT_PREFIX): $(SRC_DIR)/%.c
	@printf "$(C_YELLOW)==> Linking $< - $@$(C_RESET)\n"
	@$(CC) $(CFLAGS) $(PSRT_O) $< -o $@ $(LDFLAGS)
	@printf "$(C_GREEN)==> Linked $< - $@$(C_RESET)\n"

build_win:
	@printf "$(C_YELLOW) :: Building Windows EXE (MinGW)$(C_RESET)\n"
	@$(MAKE) \
		CC=x86_64-w64-mingw32-gcc \
		OS=windows \
		OUT_DIR=$(BIN_DIR)/windows/$(ARCH) \
		OUT_PREFIX=.exe \
		all
	@printf "$(C_GREEN) :: Builded Windows EXE$(C_RESET)\n"

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
	@echo "  all         Build executable (default)"
	@echo "  build_win   Build Windows EXE using MinGW"
	@echo "  clean       Remove build and bin directories"
	@echo "  help        Show this help message"
	@echo ""
	@echo "Build types:"
	@echo "  BUILD=debug    Debug symbols, no optimizations (default)"
	@echo "  BUILD=release  Optimized, no debug symbols"
	@echo ""