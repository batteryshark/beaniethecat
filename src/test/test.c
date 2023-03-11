// Test Suite for BeanieTheCat (FLH)
#include <stdio.h>
#include <stdlib.h>

#include <flh/flh.h>

#ifdef __linux__
#define TEST_CALLCONV  
const char* target_library = "libc.so.6";
#else
#define TEST_CALLCONV __stdcall
#include <ntdll.h>
const char* target_library = "msvcrt.dll";
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


int main(){
    printf("BeanieTheCat One Hook Test: \n");

    real_system_1 = flh_inline_hook_byname(target_library,"system",(void*)hook_system_1);
    if(real_system_1 == NULL){
        printf("Failed to Inline Hook!\n");
        return -1;
    }
    system("echo This is The One Hook Test");
   
    printf("BeanieTheCat Two Hook Test: \n");

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


