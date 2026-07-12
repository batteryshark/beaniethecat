#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <flh/flh.h>

#include "flh_internal.h"
#include "../asm/instruction_decoder.h"
#include "../platform/import_table.h"
#include "../platform/platform.h"

static unsigned int create_hotpatch_stub(void* target_address, void* redirect_address, unsigned char* hotpatch_data) {
    // Determine the difference between the target and redirect addresses.
    intptr_t difference = (intptr_t)redirect_address - (intptr_t)target_address;
    // Check if the difference fits within a 32-bit signed integer.
    if (difference >= INT32_MIN && difference <= INT32_MAX) {
        // Build a 32-bit relative jump hotpatch.
        hotpatch_data[0] = 0xE9; // jmp
        // Calculate the relative offset to the redirect address.
        int32_t relative_offset = difference - 5; // Subtract 5 for the length of the jump instruction.
        memcpy(hotpatch_data + 1, &relative_offset, sizeof(int32_t));
        hotpatch_data[5] = 0xC3; // ret
        return 6; // Length of the hotpatch.
    } else {
        // Build a 64-bit absolute jump hotpatch.
        hotpatch_data[0] = 0x49; // mov r11, imm64
        hotpatch_data[1] = 0xBB;
        memcpy(hotpatch_data + 2, &redirect_address, sizeof(void*));
        hotpatch_data[10] = 0x41; // jmp r11
        hotpatch_data[11] = 0xFF;
        hotpatch_data[12] = 0xE3;
        hotpatch_data[13] = 0xC3; // ret
        return 14; // Length of the hotpatch.
    }
}


#ifdef __x86_64__
static int create_64bit_absjmp(void* destination_address, unsigned char* jump_data) {
    uint64_t destaddr = CAST_POINTER_TO_UINT64(destination_address);
    unsigned char jmp64_template[] = {0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xFF, 0xE3};
    memcpy(&jmp64_template[2], &destaddr, sizeof(uint64_t));
    memcpy(jump_data, jmp64_template, sizeof(jmp64_template));
    return sizeof(jmp64_template);
}
#define create_absjmp create_64bit_absjmp
#else
static int create_32bit_absjmp(void* destination_address, unsigned char* jump_data){
    uint32_t destaddr = (uint32_t)destination_address;
    memcpy(jump_data, "\x68\x00\x00\x00\x00\xC3", 6);
    memcpy(jump_data + 1, &destaddr, sizeof(uint32_t));
    return 6;
}
#define create_absjmp create_32bit_absjmp
#endif

static PFLHEntry allocate_hook_entry(void* target_address) {
    PFLHEntry entry = NULL;
    if(!flh_allocate_memory(target_address, PAGE_SIZE, 1, (void**)&entry)){
        printf("[%s:%s] Error - Failed to Allocate Virtual Memory for Hook.\n",__FILE__,__FUNCTION__);
        return NULL;
    }

    memset(entry, 0, sizeof(FLHEntry));
    memcpy(entry->magic, FLH_MAGIC, sizeof(FLH_MAGIC));
    return entry;
}

static int build_inline_patch(void* target_address, PFLHEntry entry, unsigned char* hotpatch) {
    unsigned int hotpatch_jump_size = create_hotpatch_stub(target_address, entry, hotpatch);

    entry->original_target_restore_bytes_length = flh_calculate_aligned_stub_size(target_address, hotpatch_jump_size);
    if(entry->original_target_restore_bytes_length < hotpatch_jump_size){
        printf("[%s:%s] Error - Failed to Calculate Safe Patch Length.\n",__FILE__,__FUNCTION__);
        return 0;
    }

    if(entry->original_target_restore_bytes_length > sizeof(entry->original_target_restore_bytes)){
        printf("[%s:%s] Error - Original Byte Requirement Exceeds Restore Byte Length Max: %d > %zd\n",__FILE__,__FUNCTION__,entry->original_target_restore_bytes_length,sizeof(entry->original_target_restore_bytes));
        return 0;
    }

    memset(hotpatch + hotpatch_jump_size, 0x90, entry->original_target_restore_bytes_length - hotpatch_jump_size);
    memcpy(entry->original_target_restore_bytes, target_address, entry->original_target_restore_bytes_length);
    return 1;
}

static int build_inline_trampoline(void* target_address, void* redirect_function_address, PFLHEntry entry) {
    create_absjmp(redirect_function_address, entry->top_level_hook);
    memcpy(entry->original_target_trampoline, entry->original_target_restore_bytes, entry->original_target_restore_bytes_length);

    int trampoline_instruction_length = 0;
    if(entry->original_target_restore_bytes_length){
        trampoline_instruction_length = flh_sanitize_original_bytes(target_address, entry->original_target_trampoline, entry->original_target_restore_bytes_length);
    }
    if(trampoline_instruction_length == 0){
        printf("[%s:%s] Error - Failed to Build Trampoline.\n",__FILE__,__FUNCTION__);
        return 0;
    }

    unsigned char* actual_return_address = (unsigned char*)target_address + trampoline_instruction_length;
    create_absjmp(actual_return_address, entry->original_target_trampoline + trampoline_instruction_length);
    return 1;
}

static void store_iat_restore_record(PFLHEntry entry, void* real_function_address, void* target_address) {
    memcpy(entry->original_target_restore_bytes, &real_function_address, sizeof(real_function_address));
    memcpy(entry->original_target_restore_bytes + sizeof(real_function_address), &target_address, sizeof(target_address));
    entry->original_target_restore_bytes_length = FLH_IAT_RESTORE_SENTINEL;
}

static int restore_iat_hook(PFLHEntry entry) {
    void* real_function_address = NULL;
    void* original_target = NULL;
    memcpy(&real_function_address, entry->original_target_restore_bytes, sizeof(real_function_address));
    memcpy(&original_target, entry->original_target_restore_bytes + sizeof(real_function_address), sizeof(original_target));
    return flh_patch_memory(original_target, &real_function_address, sizeof(real_function_address));
}


// Reads the target function prologue, determines if this is a hooked function.
// Returns the address pointed to by the hook or NULL if not hooked.
PFLHEntry flh_get_pflh_entry(void* target_address,unsigned char is_iat_hook){

    unsigned char test_data[32];
    memcpy(test_data, target_address, sizeof(test_data));
    // Test if the target is already an entry:
    if(memcmp(test_data,FLH_MAGIC,sizeof(FLH_MAGIC)) == 0){
        return target_address;
    }
    void* flh_address = NULL;


    switch (test_data[0]) {
        case 0xE9: {
            int32_t relative_value;
            memcpy(&relative_value, test_data + 1, sizeof(relative_value));
            flh_address = (void*)((uintptr_t)target_address + relative_value + 5);
            return (PFLHEntry)flh_address;
        }
        case 0x49: {
            uint64_t absolute_value = *(uint64_t*)(test_data + 2);
            flh_address = CAST_UINT64_TO_POINTER(absolute_value);
            return (PFLHEntry)flh_address;
        }
    }
    if(!is_iat_hook){
        return NULL;
    }
    // For import-table hooks the slot holds the entry pointer directly.
    if(flh_address == NULL){
        flh_address = *(void**)target_address;
    }

    if (memcmp(FLH_MAGIC, flh_address, sizeof(FLH_MAGIC)) != 0) {
        return NULL;
    }

    return (PFLHEntry)flh_address;
}


// If a hook was already installed, update it.
void* update_hook(void* redirect_function_address, void* target_address, PFLHEntry flh_existing){

// Check if we've exceeded the number of subhooks because of course.
if(flh_existing->number_of_subhooks * sizeof(flh_existing->top_level_hook) >= sizeof(flh_existing->chain_hooks)){
    printf("[%s:%s] Error - Number of SubHooks Exceeds Maximum.\n",__FILE__,__FUNCTION__);
    return NULL;
}

// First - Copy Current Hook to Chain n-1, this will be the trampoline for this hook.
unsigned char* new_trampoline_addr = flh_existing->chain_hooks + (flh_existing->number_of_subhooks * sizeof(flh_existing->top_level_hook));
memcpy(new_trampoline_addr,flh_existing->top_level_hook,sizeof(flh_existing->top_level_hook));

// Increment Number of SubHooks
flh_existing->number_of_subhooks++;

// Create a new top level hook
create_absjmp(redirect_function_address,flh_existing->top_level_hook);

// Return the trampoline
return (void*)new_trampoline_addr;
}

void* flh_inline_hook(void* target_address, void* redirect_function_address){
// If we already hooked this before, we have to update the hook.
    PFLHEntry flh_existing = flh_get_pflh_entry(target_address,0);    
    if(flh_existing != NULL){
        return update_hook(redirect_function_address, target_address,flh_existing);
    }

    PFLHEntry pflh = allocate_hook_entry(target_address);
    if(pflh == NULL){ return NULL; }
    
    unsigned char hotpatch[64] = {0x00};
    if(!build_inline_patch(target_address, pflh, hotpatch)){ return NULL; }
    if(!build_inline_trampoline(target_address, redirect_function_address, pflh)){ return NULL; }

    if (!flh_patch_memory(target_address, hotpatch, pflh->original_target_restore_bytes_length)) { return NULL; }
    
    return (void*)pflh->original_target_trampoline;
}

void* flh_inline_hook_byname(const char* module_name, const char* function_name, void* redirect_function_address){
    // Resolve our function address and die if we can't.
    void* target_address = NULL;
    if (!flh_get_function_address(module_name, function_name, &target_address)) { return NULL; }    
    return flh_inline_hook(target_address,redirect_function_address);
}


void* flh_import_table_hook_byname(const char* module_name, const char* library_module_name, const char* function_name, void* redirect_function_address){
    // Resolve our import table entry address.

    void* target_address = flh_find_import_table_address(module_name,function_name);

    if(target_address == NULL){
        printf("[%s:%s] Error - Unable to Find Symbol: %s\n",__FILE__,__FUNCTION__,function_name);
        return NULL;
    }

    // If we already hooked this before, we have to update the hook.
    PFLHEntry flh_existing = flh_get_pflh_entry(target_address,1);    
    if(flh_existing != NULL){
        return update_hook(redirect_function_address, target_address,flh_existing);
    }
    
    PFLHEntry pflh = allocate_hook_entry(target_address);
    if(pflh == NULL){ return NULL; }

    create_absjmp(redirect_function_address,pflh->top_level_hook);

    // Resolve the real destination address of our module->function.
    void* real_function_address = NULL;
    if (!flh_get_function_address(library_module_name, function_name, &real_function_address)) { return NULL; }    

    create_absjmp(real_function_address,pflh->original_target_trampoline);

    store_iat_restore_record(pflh, real_function_address, target_address);

    if (!flh_patch_memory(target_address, &pflh, sizeof(pflh))) { return NULL; }
    return (void*)pflh->original_target_trampoline;
}

// Restores the original prologue bytes, which removes every hook on the target
// at once. It does not unwind a single link from a chain of hooks.
int flh_inline_unhook(void* target_address){
    PFLHEntry pflh = flh_get_pflh_entry(target_address,0); 
    // For now, we'll try both
    if(pflh == NULL){
        pflh = flh_get_pflh_entry(target_address,1); 
    }   
    if(pflh == NULL){
        printf("[%s:%s] Error - Unable to Unhook Function that is not Hooked.\n",__FILE__,__FUNCTION__);
        return 0;
    }    
    if(pflh->original_target_restore_bytes_length == FLH_IAT_RESTORE_SENTINEL){
        return restore_iat_hook(pflh);
    }else{
        return flh_patch_memory(target_address, pflh->original_target_restore_bytes, pflh->original_target_restore_bytes_length);
    }
}

int flh_inline_unhook_byname(const char* module_name, const char* function_name){
    // Resolve our function address and die if we can't.
    void* target_address = NULL;
    if (!flh_get_function_address(module_name, function_name, &target_address)) { return 0; }    
    return flh_inline_unhook(target_address);   
}
