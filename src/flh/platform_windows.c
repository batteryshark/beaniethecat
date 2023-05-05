#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <ntdll.h>

#include "plthook.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif


int load_library(const char* lib_name, void** h_library){
    // If we didn't specify a handle, use a throwaway one.
    if(!h_library){
        void* tmp_h_library = NULL;
        h_library = &tmp_h_library;
    }

    ANSI_STRING astr;
    astr.Length = (USHORT)strlen(lib_name);
    astr.MaximumLength = (USHORT)strlen(lib_name)+1;
    astr.Buffer = (PCHAR)lib_name;
    UNICODE_STRING u_lib_name;
    
    RtlAnsiStringToUnicodeString(&u_lib_name, &astr, TRUE);

    // NTSTATUS res = LdrGetDllHandle(NULL, 0, &u_lib_name, h_library);
    NTSTATUS res = LdrLoadDll(NULL,0,&u_lib_name,h_library);
    RtlFreeUnicodeString(&u_lib_name);
    if (res || !h_library) {return FALSE; }
    return TRUE;
   
}


int flh_get_function_address(const char* library_name, const char* function_name, void** pfunction_address) {
    if (!pfunction_address) { return 0; }
    *pfunction_address = NULL;
    void* hLibrary = NULL;
    if(!load_library(library_name,&hLibrary)){return 0;}
    ANSI_STRING astr;
    astr.Length = (USHORT)strlen(function_name);
    astr.MaximumLength = (USHORT)strlen(function_name) + 1;
    astr.Buffer = (PCHAR)function_name;
    if (LdrGetProcedureAddress(hLibrary, &astr, 0, pfunction_address)) {return FALSE;}
    if (!*pfunction_address) { return FALSE; }
    return TRUE;
   
}


int flh_allocate_memory(void* target_address, unsigned int amount_to_allocate, int memory_is_executable, void** paddress){

void* baseAddress = target_address;
if(amount_to_allocate == 0){
    amount_to_allocate = PAGE_SIZE;
}
int flags = PAGE_READWRITE;
if(memory_is_executable){
    flags = PAGE_EXECUTE_READWRITE;
}

DWORD alloc_type =  MEM_RESERVE | (MEM_COMMIT & 0xFFFFFFC0);

// If allocation fails, try to allocate in the opposite direction
void* address_scanptr = target_address;
NTSTATUS alloc_status;
while(address_scanptr != 0){
    address_scanptr -= PAGE_SIZE;
    alloc_status = NtAllocateVirtualMemory((HANDLE)-1, &address_scanptr, 0,(PSIZE_T)&amount_to_allocate, MEM_RESERVE | MEM_COMMIT & 0xFFFFFFC0, flags);
    baseAddress = address_scanptr;
    if (NT_SUCCESS(alloc_status)) {        
        break;
    }
}

if (baseAddress == NULL) {
    printf("Failed to allocate memory %04X\n",alloc_status);
    return 0;
}

*paddress = baseAddress;
return 1;
}

int flh_set_memory_permission(void* target_address, unsigned int data_amount, int flags, int* old_flags) {
    // Default to PAGE_SIZE if no len.
    if (!data_amount) { data_amount = PAGE_SIZE; }
    NTSTATUS prot_status;
    // Get the old protection flags if needed.
    SIZE_T param_data_amount = data_amount;
    ULONG pul_old_flags;
    prot_status = NtProtectVirtualMemory((HANDLE)-1, &target_address, &param_data_amount, flags, (PULONG)&pul_old_flags);
    if(!NT_SUCCESS(prot_status)){
        printf("[%s:%s] Failed to set memory protection flags: %04X\n",__FILE__,__FUNCTION__,prot_status);
        return 0;
    }
    if (old_flags != NULL) {
        *old_flags = pul_old_flags;
    }
    return 1;
}

int flh_patch_memory(void* target_address, void* patch_address, unsigned int patch_length) {
    int old_flags = 0;
    if (!flh_set_memory_permission(target_address, patch_length, PAGE_EXECUTE_READWRITE, &old_flags)) { return 0; }
    memcpy(target_address, patch_address, patch_length);
    if(old_flags){
        if (!flh_set_memory_permission(target_address, patch_length, old_flags, NULL)) { return 0; }
    }
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
return TRUE;
}

void *flh_find_import_table_address(const char *binary_image_name, const char *symbol_name) {
    plthook_t* plthook;
    unsigned int pos = 0;
    const char* name;    
    
    void* handle = NULL;
    
    if(!load_library(binary_image_name,&handle)){return NULL;}
    
    plthook_open_by_handle(&plthook, handle);
    void **addr = NULL;
     while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        if(name != NULL && !strcmp(name,symbol_name)){
            return (void*)addr;
        }
    }
    return NULL;
}
