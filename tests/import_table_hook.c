#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
static int hook_1_call_count = 0;
static int hook_2_call_count = 0;
static const char* last_hook_1_command = NULL;
static const char* last_hook_2_command = NULL;

int TEST_CALLCONV hook_system_1(const char* command) {
    hook_1_call_count++;
    last_hook_1_command = command;
    return real_system_1(command);
}


int TEST_CALLCONV hook_system_2(const char* command) {
    hook_2_call_count++;
    last_hook_2_command = command;
    return real_system_2(command);
}


int main(){
    real_system_1 = flh_import_table_hook_byname(NULL,target_library,"system",(void*)hook_system_1);
    assert(real_system_1 != NULL);

    assert(system("echo This is The One Hook Test") == 0);
    assert(hook_1_call_count == 1);
    assert(hook_2_call_count == 0);
    assert(strcmp(last_hook_1_command, "echo This is The One Hook Test") == 0);

    real_system_2 = flh_import_table_hook_byname(NULL,target_library,"system",(void*)hook_system_2);
    assert(real_system_2 != NULL);

    assert(system("echo This is The Two Hook Test") == 0);
    assert(hook_1_call_count == 2);
    assert(hook_2_call_count == 1);
    assert(strcmp(last_hook_1_command, "echo This is The Two Hook Test") == 0);
    assert(strcmp(last_hook_2_command, "echo This is The Two Hook Test") == 0);

    #ifndef __linux__
        assert(flh_inline_unhook_byname(target_library,"system"));
    #else
        assert(flh_inline_unhook((void*)system));
    #endif

    assert(system("echo This is The Unhook Test") == 0);
    assert(hook_1_call_count == 2);
    assert(hook_2_call_count == 1);

    return 0;
}
