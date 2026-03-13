#pragma once

#include <stdio.h>
#include <stdbool.h>

typedef struct {
    FILE* stream;
    const char* fmt;
    bool active;
} PTL_LOG_STREAM;

typedef enum {
    PTL_LOG_TYPE_WARN,
    PTL_LOG_TYPE_ERROR,
    PTL_LOG_TYPE_INFO,
    PTL_LOG_TYPE_TIP
} PTL_LOG_TYPE;

void __ptl_log(PTL_LOG_STREAM* stream,  PTL_LOG_TYPE type, char* msg);
void __ptl_logf(PTL_LOG_STREAM* stream,  PTL_LOG_TYPE type, char* fmt, ...);
