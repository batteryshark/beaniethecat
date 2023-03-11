// Capstone-Assisted Assembly Analysis Module for FLH
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <capstone/capstone.h>

#include <flh/flh.h>
#include <flh/asm.h>

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
    if(instruction_count < 0){
        printf("[%s:%s] Capstone Unable to Parse Assembly\n",__FILE__,__FUNCTION__);
        return 0;
    }

    // Handle all the weirdness in a way that won't break our stuff coming back.
    unsigned int instruction_offset = 0;
    for(int i=0;i<instruction_count;i++){

        // If this is an endbr32/endbr64 instruction (CET), we're going to just fill 4 bytes of the trampoline with NOP because fuck it.
        if(instructions[i].id == X86_INS_ENDBR32 || instructions[i].id == X86_INS_ENDBR64){
            memset((unsigned char*)sanitized_code_address+instruction_offset,0x90,instructions[i].size);
            instruction_offset += instructions[i].size;
            continue;
        }


        // We're going to look for relative addresses and fix those too.
        if ((instructions[i].id == X86_INS_CALL || instructions[i].id == X86_INS_JMP) || 
   (instructions[i].detail && instructions[i].detail->x86.op_count > 0 &&
    (instructions[i].detail->x86.operands[0].type == X86_OP_MEM || instructions[i].detail->x86.operands[0].type == X86_OP_IMM))){

        // FOR NOW - If it isn't a jump or call, we're gonna skip it.
        if(instructions[i].id != X86_INS_CALL && instructions[i].id != X86_INS_JMP){
            printf("[%s:%s] Relative Address Instruction May Require Fix at %p\n",__FILE__,__FUNCTION__,original_address);
            instruction_offset += instructions[i].size;
            continue;
        }

        // Calculate the absolute address from the operand.
        void* absolute_destination_address = (unsigned char*)original_address + instructions[i].detail->x86.operands[0].imm;
        void* post_instruction_address = (unsigned char*)sanitized_code_address + (instruction_offset + instructions[i].size);
    
        #ifdef __x86_64__
        int64_t original_relative_offset = instructions[i].detail->x86.operands[0].imm - (instruction_offset + instructions[i].size);
        int64_t new_relative_offset = (uintptr_t)absolute_destination_address - (uintptr_t)post_instruction_address;
        #else
        int32_t original_relative_offset = instructions[i].detail->x86.operands[0].imm - (instruction_offset + instructions[i].size);
        int32_t new_relative_offset = (uintptr_t)absolute_destination_address - (uintptr_t)post_instruction_address;
        #endif

        intptr_t offset_difference = (uintptr_t)absolute_destination_address - (uintptr_t)post_instruction_address;
        
        if (offset_difference < INT32_MIN && offset_difference > INT32_MAX) {
            printf("[%s:%s] Error: Offset Difference Exceeds 32bit Value: %zx\n",__FILE__,__FUNCTION__,offset_difference);
            exit(-1);        
        }
    
        // Update the instruction's operand
        //printf("[%s:%s] FIXUP: %08X => %08X Original Function: %p New Function: %p Dest: %p \n", __FILE__,__FUNCTION__,original_relative_offset, new_relative_offset, original_address,sanitized_code_address,absolute_destination_address);
        
        memcpy((unsigned char*)post_instruction_address - sizeof(int32_t), &new_relative_offset, sizeof(int32_t));

        }   
        instruction_offset += instructions[i].size;
    }
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

    if(instruction_count < 0){
        printf("[%s:%s] Capstone Unable to Parse Assembly\n",__FILE__,__FUNCTION__);
        return 0 ;
    }

    for(int i=0;i<instruction_count;i++){
        aligned_stub_size += instructions[i].size;
        if(aligned_stub_size >= hotpatch_length){
            break;
        }
    }
    return aligned_stub_size;
}