#pragma once

#ifndef PHEONIX_CORE_PTL
#define PHEONIX_CORE_PTL

#include <stdint.h>
#include <stddef.h>

typedef enum {
    PTL_ARCH_x86,
    PTL_ARCH_x86_64,
} PTL_Architecture;

typedef struct {
    PTL_Architecture Architecture;

    void* CPUState;
    uint8_t* Memory;
    uint64_t MemorySize;
} PTL_Context;

PTL_Context* create_ctx(PTL_Architecture arch, size_t mem_size);
void delete_ctx(PTL_Context* ctx);

#endif