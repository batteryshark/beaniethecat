// Capstone-Assisted Assembly Analysis Module for FLH
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <capstone/capstone.h>

#include "instruction_decoder.h"

// Thanks to http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html for the inspiration on this.

int flh_sanitize_original_bytes(void* original_address,void* sanitized_code_address, unsigned int code_size){
    csh cs_handle;

    #ifdef __x86_64__
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {return 0;}
    #else
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) {return 0;}
    #endif

    // Enable Capstone's "DETAIL" mode
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* instructions; 
    size_t instruction_count = cs_disasm(cs_handle, sanitized_code_address, code_size, 0, 0, &instructions);
    if(instruction_count == 0){
        printf("[%s:%s] Capstone Unable to Parse Assembly\n",__FILE__,__FUNCTION__);
        cs_close(&cs_handle);
        return 0;
    }

    // Handle all the weirdness in a way that won't break our stuff coming back.
    unsigned int instruction_offset = 0;
    for(int i=0;i<instruction_count;i++){

        // endbr32/endbr64 (CET) only matters as a landing pad at the real entry.
        // Inside the copied trampoline it is unneeded, so replace it with NOPs.
        if(instructions[i].id == X86_INS_ENDBR32 || instructions[i].id == X86_INS_ENDBR64){
            memset((unsigned char*)sanitized_code_address+instruction_offset,0x90,instructions[i].size);
            instruction_offset += instructions[i].size;
            continue;
        }

        // Only RELATIVE branches need relocation: a jump/call whose first operand
        // is an immediate (the relative target). This includes conditional jumps
        // (Jcc) via the JUMP group. Indirect/absolute forms like
        //   FF 25 [__imp_WriteFile]   (jmp dword ptr [abs])
        // have a MEM operand and are position-independent - they MUST be copied
        // verbatim. Relocating them (the previous bug) overwrites the absolute
        // pointer with a bogus rel32 and corrupts the trampoline.
        unsigned char is_branch = cs_insn_group(cs_handle, &instructions[i], X86_GRP_JUMP) ||
                                  cs_insn_group(cs_handle, &instructions[i], X86_GRP_CALL);
        unsigned char rel_target = instructions[i].detail && instructions[i].detail->x86.op_count > 0 &&
                                   instructions[i].detail->x86.operands[0].type == X86_OP_IMM;

        if (is_branch && rel_target) {
            // The relative displacement is the last byte(s) of the instruction:
            // rel8 forms (EB/E3/7x) are 2 bytes; near forms (E8/E9 = 5, 0F8x = 6)
            // carry a rel32. A rel8 target is within +/-127 of the original site,
            // so once the trampoline sits far away it can no longer be expressed
            // as rel8 in place. Rather than corrupt it, bail (caller can fall back
            // to another hook method for that rare prologue).
            unsigned int disp_size = (instructions[i].size >= 5) ? 4u : 1u;
            if (disp_size != 4u) {
                printf("[%s:%s] rel8 branch in prologue at %p+%u; cannot build trampoline.\n",
                       __FILE__,__FUNCTION__,original_address,instruction_offset);
                cs_free(instructions, instruction_count);
                cs_close(&cs_handle);
                return 0;
            }

            void* absolute_destination_address = (unsigned char*)original_address + instructions[i].detail->x86.operands[0].imm;
            void* post_instruction_address = (unsigned char*)sanitized_code_address + (instruction_offset + instructions[i].size);
            intptr_t offset_difference = (uintptr_t)absolute_destination_address - (uintptr_t)post_instruction_address;

            if (offset_difference < INT32_MIN || offset_difference > INT32_MAX) {
                printf("[%s:%s] Error: Offset Difference Exceeds 32bit Value: %zx\n",__FILE__,__FUNCTION__,offset_difference);
                cs_free(instructions, instruction_count);
                cs_close(&cs_handle);
                return 0;
            }

            int32_t new_relative_offset = (int32_t)offset_difference;
            memcpy((unsigned char*)post_instruction_address - sizeof(int32_t), &new_relative_offset, sizeof(int32_t));
        }
        // Everything else (incl. FF /4, FF /5 indirect jumps and normal
        // instructions) is position-independent in the prologue and copied as-is.
        instruction_offset += instructions[i].size;
    }
    cs_free(instructions, instruction_count);
    cs_close(&cs_handle);
    return instruction_offset;
}


unsigned int flh_calculate_aligned_stub_size(void* target_address, unsigned int hotpatch_length){
    csh cs_handle;
    unsigned int aligned_stub_size = 0;
    #ifdef __x86_64__
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {return 0;}
    #else
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) {return 0;}
    #endif
    cs_insn* instructions;
    size_t instruction_count = cs_disasm(cs_handle, target_address, 32, 0, 0, &instructions);

    if(instruction_count == 0){
        printf("[%s:%s] Capstone Unable to Parse Assembly\n",__FILE__,__FUNCTION__);
        cs_close(&cs_handle);
        return 0 ;
    }

    for(int i=0;i<instruction_count;i++){
        aligned_stub_size += instructions[i].size;
        if(aligned_stub_size >= hotpatch_length){
            break;
        }
    }
    cs_free(instructions, instruction_count);
    cs_close(&cs_handle);
    return aligned_stub_size;
}
