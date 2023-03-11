// Linux-Specific Utility Functions
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

int flh_get_function_address(const char* library_name, const char* function_name, void** pfunction_address) {
    // If we didn't specify a place to store the function address, we can't do anything.
    if (pfunction_address == NULL) { return 0; }
    
    // Open our library or die.
    void* hLibrary = dlopen(library_name, RTLD_NOW);
    if(hLibrary == NULL){return 0;}
    // Resolve our Symbol
    *pfunction_address = dlsym(hLibrary,function_name);
    // If we didn't resolve our symbol - die.
    if(*pfunction_address == NULL){return 0;}

    return 1;
}

int flh_allocate_memory(void* target_proximity, unsigned int amount_to_allocate, int memory_is_executable, void** paddress) {
    // If we didn't specify an allocation address, we can't do anything.
    if(paddress == NULL){ return 0;}
    // If we didn't specify an amount of memory to allocate, we'll assume 1 page.
    if (amount_to_allocate == 0) {amount_to_allocate = PAGE_SIZE;}
    // If memory is executable, we'll specify the appropriate flags.
    unsigned int access_mask = PROT_READ | PROT_WRITE;
    if(memory_is_executable){
        access_mask |= PROT_EXEC;
    }
    // Set up Our Flags
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    // Actually allocate the memory we want.
    *paddress = mmap(target_proximity, amount_to_allocate, access_mask, flags, 0, 0);    
    // The mmap() failed.
    if(*paddress == NULL){
        return 0;
    }
    return 1;
}

int flh_set_memory_permission(void* target_address, unsigned int data_amount, int flags, int* old_flags) {
    // Default to PAGE_SIZE if no len.
    if (data_amount == 0) {
        data_amount = PAGE_SIZE;
    }
    
    // Calculate the page-aligned starting address for the target memory region.
    void* page_aligned_address = (void*)((uintptr_t)target_address & ~(PAGE_SIZE - 1));
    

    
    // Save the current protection flags if necessary.    
    if (old_flags != NULL) {
        // mincore was introduced in glibc 2.19
        #if defined(__GLIBC__) && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 19)))
        // Get the current protection flags for the memory region.
        unsigned char mincore_vec = 0;
        if (mincore(page_aligned_address, data_amount, &mincore_vec) == -1) {
            printf("[%s:%s] Failed to Get Existing Memory Permission\n",__FILE__,__FUNCTION__);
            return 0; // Failed to get protection flags.
        }        
        
        *old_flags = ((int)mincore_vec & 0x1) ? PROT_EXEC : 0;
        *old_flags |= ((int)mincore_vec & 0x2) ? PROT_WRITE : 0;
        *old_flags |= PROT_READ;        
        #endif
        //printf("[%s:%s] Old Protect Flags: %04X\n",__FILE__,__FUNCTION__,*old_flags);
    }
    
    // Update the protection flags for the memory region.
    if (mprotect(page_aligned_address, data_amount, flags) == -1) {
        return 0; // Failed to set protection flags.
    }
    
    return 1;
}

int flh_patch_memory(void* target_address, void* patch_address, unsigned int patch_length) {
    int old_flags = 0;
    if (!flh_set_memory_permission(target_address, patch_length, PROT_READ | PROT_WRITE | PROT_EXEC, &old_flags)) { return 0; }
    memcpy(target_address, patch_address, patch_length);
    if(old_flags){
        if (!flh_set_memory_permission(target_address, patch_length, old_flags, NULL)) { return 0; }
    }
    return 1;
}