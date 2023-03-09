// Test Suite for BeanieTheCat Library (FLH)
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#ifdef __x86_64__
const char* library_path = "./libbeanie64.so";
#else
const char* library_path = "./libbeanie32.so";
#endif

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


typedef void* (*hook_func_t)(const char*, const char*, void*);
typedef int (*unhook_func_t)(void*);

hook_func_t flh_hook; 
unhook_func_t flh_unhook;


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

int main(){
    printf("BeanieTheCat Lib One Hook Test: \n");
    if(!get_function_address(library_path,"flh_inline_hook",(void**)&flh_hook)){
        printf("Error Resolving Hook Address From Library!\n");
        return -1;
    }
    if(!get_function_address(library_path,"flh_inline_unhook",(void**)&flh_unhook)){
        printf("Error Resolving Unhook Address From Library!\n");
        return -1;
    }    

    real_system_1 = flh_hook("libc.so.6","system",(void*)hook_system_1);

    system("echo This is The One Hook Test");
   
    printf("BeanieTheCat Lib Two Hook Test: \n");

    real_system_2 = flh_hook("libc.so.6","system",(void*)hook_system_2);

    system("echo This is The Two Hook Test");

    printf("Unhook Test\n");

    flh_unhook((void*)system);

    system("echo This is The Unhook Test");

    printf("Done!\n");

return 0;
}


