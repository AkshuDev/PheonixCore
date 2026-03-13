#pragma once

#include <stdint.h>

typedef struct {
    uint64_t Registers[16];
    uint64_t RIP;
    uint64_t RFLAGS;
} PTL_X86CPUState;