#pragma once 

int flh_get_function_address(const char* library_name, const char* function_name, void** pfunction_address);
int flh_allocate_memory(void* target_proximity, unsigned int amount_to_allocate, int memory_is_executable, void** paddress);
int flh_set_memory_permission(void* target_address, unsigned int data_amount, int flags, int* old_flags);
int flh_patch_memory(void* target_address, void* patch_address, unsigned int patch_length);
void *flh_find_import_table_address(const char *binary_image_name, const char *symbol_name);