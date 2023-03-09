// Test Suite for BeanieTheCat (FLH)
#include <stdio.h>
#include <stdlib.h>

#include <flh/flh.h>


typedef int (*system_func_t)(const char*);
static system_func_t real_system_1 = NULL;
static system_func_t real_system_2 = NULL;

int hook_system_1(const char* command) {
    printf("[%s:%s] system() Called with Command: %s\n",__FILE__, __FUNCTION__, command);
    return real_system_1(command);
}


int hook_system_2(const char* command) {
    printf("[%s:%s] system() Called with Command: %s\n",__FILE__, __FUNCTION__, command);
    return real_system_2(command);
}


int main(){
    printf("BeanieTheCat One Hook Test: \n");

    real_system_1 = flh_inline_hook("libc.so.6","system",(void*)hook_system_1);

    system("echo This is The One Hook Test");
   
    printf("BeanieTheCat Two Hook Test: \n");

    real_system_2 = flh_inline_hook("libc.so.6","system",(void*)hook_system_2);

    system("echo This is The Two Hook Test");

    printf("Unhook Test\n");

    flh_inline_unhook((void*)system);

    system("echo This is The Unhook Test");

    printf("Done!\n");

return 0;
}


