#pragma once

void* flh_inline_hook(void* target_address, void* redirect_function_address);
void* flh_import_table_hook_byname(const char* module_name, const char* library_module_name, const char* function_name, void* redirect_function_address);
void* flh_inline_hook_byname(const char* module_name, const char* function_name, void* redirect_function_address);

int flh_inline_unhook_byname(const char* module_name, const char* function_name);
int flh_inline_unhook(void* target_address);
