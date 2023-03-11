// Test Suite for BeanieTheCat Library (FLH)
#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__
#include <dlfcn.h>
#define TEST_CALLCONV 
const char* target_library = "libc.so.6";
const char* library_path = "./libflh.so";

#else
#include <ntdll.h>
const char* target_library = "msvcrt.dll";
#define TEST_CALLCONV __stdcall
const char* library_path = "flh.dll";
#endif

typedef int (*system_func_t)(const char*);
static system_func_t real_system_1 = NULL;
static system_func_t real_system_2 = NULL;

int TEST_CALLCONV hook_system_1(const char* command) {
    printf("[%s:%s] system() Called with Command: %s\n",__FILE__, __FUNCTION__, command);
    return real_system_1(command);
}


int TEST_CALLCONV hook_system_2(const char* command) {
    printf("[%s:%s] system() Called with Command: %s\n",__FILE__, __FUNCTION__, command);
    return real_system_2(command);
}


typedef void* (*flh_inline_hook_byname_t)(const char*, const char*, void*);
typedef void* (*flh_inline_hook_t)(void*, void*);
typedef int (*flh_inline_unhook_byname_t)(const char*, const char*);
typedef int (*flh_inline_unhook_t)(void*);

flh_inline_hook_byname_t flh_inline_hook_byname;
flh_inline_unhook_byname_t flh_inline_unhook_byname;
flh_inline_hook_t flh_inline_hook;
flh_inline_unhook_t flh_inline_unhook;

#ifdef __linux__
int get_function_address(const char* library_name, const char* function_name, void** pfunction_address) {
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
#else
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


int get_function_address(const char* library_name, const char* function_name, void** pfunction_address) {
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
#endif

int main(){
    printf("BeanieTheCat Lib One Hook Test: \n");
    if(!get_function_address(library_path,"flh_inline_hook_byname",(void**)&flh_inline_hook_byname)){
        printf("Error Resolving Hook By Name From Library!\n");
        return -1;
    }
    if(!get_function_address(library_path,"flh_inline_hook",(void**)&flh_inline_hook)){
        printf("Error Resolving Hook By Address From Library!\n");
        return -1;
    }    
    if(!get_function_address(library_path,"flh_inline_unhook",(void**)&flh_inline_unhook)){
        printf("Error Resolving Unhook By Address From Library!\n");
        return -1;
    }    
    if(!get_function_address(library_path,"flh_inline_unhook_byname",(void**)&flh_inline_unhook_byname)){
        printf("Error Resolving Unhook By Name From Library!\n");
        return -1;
    }    
    real_system_1 = flh_inline_hook_byname(target_library,"system",(void*)hook_system_1);

    system("echo This is The One Hook Test");
   
    printf("BeanieTheCat Lib Two Hook Test: \n");

    real_system_2 = flh_inline_hook_byname(target_library,"system",(void*)hook_system_2);

    system("echo This is The Two Hook Test");

    printf("Unhook Test\n");
    // Windows for some functions tends to create references to stubs that jump to the real function.
    #ifndef __linux__
        flh_inline_unhook_byname(target_library,"system");
    #else
        flh_inline_unhook((void*)system);
    #endif
    
    system("echo This is The Unhook Test");

    printf("Done!\n");

return 0;
}


