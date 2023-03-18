// Logic for Filthy Little Hooker [BeanieTheCat]
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include <flh/asm.h>
#include <flh/platform.h>
#include <flh/flh.h>

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
    //printf("[%s:%s] %p \n",__FILE__,__FUNCTION__,destination_address);

    return sizeof(jmp64_template);
}
static void* deconstruct_absjmp(unsigned char* jump_data){
    if(jump_data == NULL){return NULL;}
    return *(unsigned char**)jump_data+2;
}
#define create_absjmp create_64bit_absjmp
#else
static int create_32bit_absjmp(void* destination_address, unsigned char* jump_data){
    uint32_t destaddr = (uint32_t)destination_address;
    memcpy(jump_data, "\x68\x00\x00\x00\x00\xC3", 6);
    memcpy(jump_data + 1, &destaddr, sizeof(uint32_t));
    return 6;
}
static void* deconstruct_absjmp(unsigned char* jump_data){
    if(jump_data == NULL){return NULL;}
    return *(unsigned char**)jump_data+1;
}
#define create_absjmp create_32bit_absjmp
#endif


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
            break;
        }
        case 0x49: {
            uint64_t absolute_value = *(uint64_t*)(test_data + 2);
            flh_address = CAST_UINT64_TO_POINTER(absolute_value);
            break;
        }
    }
    if(!is_iat_hook){
        //printf("[%s:%s] Not a FLH Hooked Function %p\n", __FILE__, __FUNCTION__, target_address);
        return NULL;
    }
    // Added for IAT
    if(flh_address == NULL){
        flh_address = *(void**)target_address;
    }
    
    if (memcmp(FLH_MAGIC, flh_address, sizeof(FLH_MAGIC)) != 0) {
        //printf("[%s:%s] Not a FLH Hooked Function %p\n", __FILE__, __FUNCTION__, target_address);
        return NULL;
    }

    return (PFLHEntry)flh_address;
}


// If a hook was already installed, update it.
void* update_hook(void* redirect_function_address, void* target_address, PFLHEntry flh_existing){

// Check if we've exceeded the number of subhooks because of course.
if(flh_existing->number_of_subhooks * sizeof(flh_existing->top_level_hook) > sizeof(flh_existing->chain_hooks)){
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

    // Next - We need to attempt to allocate a page near our target.
    PFLHEntry pflh =  NULL;
    if(!flh_allocate_memory(target_address,PAGE_SIZE,1,(void**)&pflh)){
        printf("[%s:%s] Error - Failed to Allocate Virtual Memory for Hook.\n",__FILE__,__FUNCTION__);
        return NULL;
    }
    memset(pflh,0,sizeof(FLHEntry));

    // Copy our Magic - The Ramp and NOPNOPNOPNOP:3
    memcpy(pflh->magic,FLH_MAGIC,sizeof(FLH_MAGIC));
    
    // We only need this logic if we're hooking and making an FLHEntry for the first time.
    unsigned char hotpatch[64] = {0x00};

    // Build our HotPatch Jump        
    unsigned int hotpatch_jump_size = create_hotpatch_stub(target_address,pflh,hotpatch);
    
    // Determine the Total Aligned Size of Our HotPatch
    pflh->original_target_restore_bytes_length = flh_calculate_aligned_stub_size(target_address, hotpatch_jump_size);
    
    if(pflh->original_target_restore_bytes_length > sizeof(pflh->original_target_restore_bytes)){
        printf("[%s:%s] Error - Original Byte Requirement Exceeds Restore Byte Length Max: %d > %zd\n",__FILE__,__FUNCTION__,pflh->original_target_restore_bytes_length,sizeof(pflh->original_target_restore_bytes));
        return NULL;
    }
    // Fill our HotPatch with NOPs Post-HotPatch
    memset(hotpatch + hotpatch_jump_size, 0x90, pflh->original_target_restore_bytes_length - hotpatch_jump_size);

    // Copy a backup of our original bytes that we're going to overwrite.
    memcpy(pflh->original_target_restore_bytes,target_address,pflh->original_target_restore_bytes_length);

    
    // Fill in the Hook Jump Code
    create_absjmp(redirect_function_address,pflh->top_level_hook);

    // Fill in the Trampoline Code
    // Write our stolen instructions to the head of the trampoline.
    memcpy(pflh->original_target_trampoline, pflh->original_target_restore_bytes, pflh->original_target_restore_bytes_length);
    
    // Clean up Our Original Bytes - Fix Offsets, Nuke CET Stuff, etc.
    int trampoline_instruction_length = 0;
    if(pflh->original_target_restore_bytes_length){
        trampoline_instruction_length = flh_sanitize_original_bytes(target_address,pflh->original_target_trampoline, pflh->original_target_restore_bytes_length);
    }

    // Calculate our "Resume Address" - that is, the target address after our stolen bytes.
    unsigned char* actual_return_address = (unsigned char*)target_address + trampoline_instruction_length;
    
    // Create our Trampoline Jump after the stolen bytes.
    create_absjmp(actual_return_address,pflh->original_target_trampoline + trampoline_instruction_length);

    // Copy our HotPatch to Overwrite Our Original Function Prologue
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
    
    // Next - We need to attempt to allocate a page near our target.
    PFLHEntry pflh =  NULL;
    if(!flh_allocate_memory(target_address,PAGE_SIZE,1,(void**)&pflh)){
        printf("[%s:%s] Error - Failed to Allocate Virtual Memory for Hook.\n",__FILE__,__FUNCTION__);
        return NULL;
    }
    memset(pflh,0,sizeof(FLHEntry));

    // Copy our Magic - The Ramp and NOPNOPNOPNOP:3
    memcpy(pflh->magic,FLH_MAGIC,sizeof(FLH_MAGIC));

    // Fill in the Hook Jump Code
    create_absjmp(redirect_function_address,pflh->top_level_hook);

    // Resolve the real destination address of our module->function.
    void* real_function_address = NULL;
    if (!flh_get_function_address(library_module_name, function_name, &real_function_address)) { return NULL; }    

    // Create our Trampoline Jump after the stolen bytes.
    create_absjmp(real_function_address,pflh->original_target_trampoline);

    // Copy a backup of our original bytes that we're going to overwrite.
    memcpy(pflh->original_target_restore_bytes,&real_function_address,sizeof(void*));
    memcpy(&pflh->original_target_restore_bytes[8],&target_address,sizeof(void*));
    pflh->original_target_restore_bytes_length = 0xFFFFFFFF;

    // Finally, add the address to our FLHEntry as the target on our import entry.
    //if (!flh_patch_memory(target_address,(unsigned char*)&pflh, sizeof(unsigned char*))) { return NULL; }    
    uintptr_t *got_entry = (uintptr_t *)target_address;
    *got_entry = (uintptr_t)pflh;
    return (void*)pflh->original_target_trampoline;
}

// For now, we'll just restore the original bytes to remove the hook.
// TODO Later - Remove and Relink Parts of Hooks
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
    // If the length is 0xFFFFFFFF - This was an IAT Patch and the restore bytes are static.
    if(pflh->original_target_restore_bytes_length == 0xFFFFFFFF){
        void* real_function_address = pflh->original_target_restore_bytes;
        void* original_target = pflh->original_target_restore_bytes+8;
        return flh_patch_memory(original_target,&real_function_address,sizeof(void*));
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