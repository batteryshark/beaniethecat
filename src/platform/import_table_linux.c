#include <dlfcn.h>
#include <stddef.h>
#include <string.h>

#include "import_table.h"
#include "plthook.h"

static int flh_symbol_matches(const char* candidate_name, const char* symbol_name) {
    size_t symbol_name_length = strlen(symbol_name);
    return strncmp(candidate_name, symbol_name, symbol_name_length) == 0 &&
           (candidate_name[symbol_name_length] == '\0' || candidate_name[symbol_name_length] == '@');
}

void* flh_find_import_table_address(const char* binary_image_name, const char* symbol_name) {
    plthook_t* plthook;
    int pos = 0;
    const char* name;
    void** addr = NULL;

    if (binary_image_name == NULL) {
        if (plthook_open(&plthook, NULL) != 0) {
            return NULL;
        }
    } else {
        void* handle = dlopen(binary_image_name, RTLD_LAZY);
        if (handle == NULL) { return NULL; }
        if (plthook_open_by_handle(&plthook, handle) != 0) {
            return NULL;
        }
    }

    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        if (name != NULL && flh_symbol_matches(name, symbol_name)) {
            plthook_close(plthook);
            return (void*)addr;
        }
    }
    plthook_close(plthook);
    return NULL;
}
