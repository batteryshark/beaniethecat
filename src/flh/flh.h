#pragma once

#include <stdint.h>

#define PAGE_SIZE 0x1000

#ifdef _LP64
    #define CAST_POINTER_TO_UINT64(p) ((uint64_t)(p))
    #define CAST_UINT64_TO_POINTER(u) ((void *)(u))
#else
    #define CAST_POINTER_TO_UINT64(p) ((uint64_t)(uint32_t)(p))
    #define CAST_UINT64_TO_POINTER(u) ((void *)(uint32_t)(u))
#endif

typedef struct _FLH_ENTRY{
	uint8_t  magic[8];
	uint32_t number_of_subhooks;
	uint32_t original_target_restore_bytes_length;
	uint8_t  top_level_hook[16];
	uint8_t  original_target_trampoline[112];
	uint8_t  original_target_restore_bytes[112];
	uint8_t  chain_hooks[0xF00]; ///...
}FLHEntry,*PFLHEntry;

static const unsigned char FLH_MAGIC[8] = {0xEB, 0x0E, 0x90, 0x90, 0x90, 0x90, 0x3A, 0x33};

void* flh_inline_hook(const char* module_name, const char* function_name, void* redirect_function_address);
int flh_inline_unhook(void* target_address);
