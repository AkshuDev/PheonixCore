#pragma once

#include <stdint.h>

#define PTL_MAX_IR 128

typedef enum {
    PTL_OP_NOP,
    PTL_OP_MOV,
    PTL_OP_ADD,
    PTL_OP_SUB,
    PTL_OP_LOAD,
    PTL_OP_STORE,
    PTL_OP_JMP,
    PTL_OP_CMP,
    PTL_OP_CALL,
    PTL_OP_RET
} PTL_Opcode;

typedef struct {
    PTL_Opcode Opcode;

    uint32_t Dest;
    uint32_t Src1;
    uint32_t Src2;
} PTL_IRInstruction;

typedef struct {
    uint64_t GuestPC;

    PTL_IRInstruction Instructions[PTL_MAX_IR];
    uint32_t InstructionCount;
} PTL_Block;