#pragma once

#ifndef PHEONIX_CORE_PTL
#define PHEONIX_CORE_PTL
#endif

typedef enum {
    PTL_ARCH_x86,
    PTL_ARCH_x86_64,
} PTL_Architecture;

typedef struct {
    PTL_Architecture architecture;
    
} PTL_Context;