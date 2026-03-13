#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ptl.h>

PTL_Context* create_ctx(PTL_Architecture arch, size_t mem_size) {
    switch (arch) {
        case PTL_ARCH_x86: break;
        case PTL_ARCH_x86_64: break;
        default: return NULL;
    }

    PTL_Context* ctx = malloc(sizeof(PTL_Context));
    if (!ctx) return NULL;
}