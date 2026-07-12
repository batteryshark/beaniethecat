TARGETS_LIB = nix32_lib nix64_lib win32_lib win64_lib
TARGETS_TEST = nix32_test nix64_test win32_test win64_test

.PHONY: $(TARGETS_LIB) $(TARGETS_TEST) lib test clean help

help:
	@echo "Available targets: nix32, nix64, win32, win64 -- lib or test"
	@echo "  lib  - Build libraries for all platforms"
	@echo "  test - Build test executables for all platforms"
	@echo "  e.g. make nix32_lib or make win64_test"	

# We'll define this first and add to it for Windows.
FLH_FLAGS := -lcapstone -static-libgcc

ifeq ($(findstring nix32,$(MAKECMDGOALS)),nix32)
  TARGET_PLATFORM := nix32
  TARGET_OS := linux
  FLH_FLAGS := $(FLH_FLAGS) -ldl
  PLT_SRCS := third_party/plthook/plthook_elf.c
endif

ifeq ($(findstring nix64,$(MAKECMDGOALS)),nix64)
  TARGET_PLATFORM := nix64
  TARGET_OS := linux
  FLH_FLAGS := $(FLH_FLAGS) -ldl
  PLT_SRCS := third_party/plthook/plthook_elf.c
endif

ifeq ($(findstring win32,$(MAKECMDGOALS)),win32)
  TARGET_PLATFORM := win32
  TARGET_OS := windows
  FLH_FLAGS := $(FLH_FLAGS) -lntdll -ldbghelp
  PLT_SRCS := third_party/plthook/plthook_win32.c
endif

ifeq ($(findstring win64,$(MAKECMDGOALS)),win64)
  TARGET_PLATFORM := win64
  TARGET_OS := windows
  FLH_FLAGS := $(FLH_FLAGS) -lntdll -ldbghelp
  PLT_SRCS := third_party/plthook/plthook_win32.c
endif

BUILD_ROOT := ./build
BUILD_PATH := $(BUILD_ROOT)/$(TARGET_PLATFORM)

LIB_PATH := -L third_party/capstone/lib/$(TARGET_PLATFORM)
PLATFORM_SRCS := src/platform/$(TARGET_OS).c src/platform/import_table_$(TARGET_OS).c
FLH_SRCS := $(PLT_SRCS) src/asm/instruction_decoder.c src/core/flh.c $(PLATFORM_SRCS)
FLH_INCLUDES := -I include -I src -I src/core -I src/asm -I src/platform -I third_party/plthook -I third_party/ntdll -I third_party/capstone/include

# Linux Targets
## -- 32bit
nix32_lib:
	mkdir -p $(BUILD_PATH)
	cc -m32 -shared -fPIC $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/libflh.so
nix32_test: nix32_lib
	cc -m32 tests/inline_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.elf
	cc -m32 tests/import_table_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test_iat.elf
	cc -m32 tests/dynamic_library.c $(FLH_INCLUDES) -ldl -o $(BUILD_PATH)/test_library.elf
## -- 64bit
nix64_lib:
	mkdir -p $(BUILD_PATH)
	cc -shared -fPIC $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/libflh.so
nix64_test:	nix64_lib
	cc tests/inline_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.elf
	cc tests/import_table_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test_iat.elf
	cc tests/dynamic_library.c $(FLH_INCLUDES) -ldl -o $(BUILD_PATH)/test_library.elf

# Windows Targets
## -- 32bit
win32_lib:
	mkdir -p $(BUILD_PATH)
	i686-w64-mingw32-gcc -shared $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/flh.dll
win32_test: win32_lib
	i686-w64-mingw32-gcc tests/inline_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.exe
	i686-w64-mingw32-gcc tests/import_table_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test_iat.exe
	i686-w64-mingw32-gcc tests/dynamic_library.c $(FLH_INCLUDES) -lntdll  -o $(BUILD_PATH)/test_library.exe
## -- 64bit
win64_lib:
	mkdir -p $(BUILD_PATH)
	x86_64-w64-mingw32-gcc -shared $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/flh.dll
win64_test: win64_lib
	x86_64-w64-mingw32-gcc tests/inline_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.exe
	x86_64-w64-mingw32-gcc tests/import_table_hook.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test_iat.exe
	x86_64-w64-mingw32-gcc tests/dynamic_library.c $(FLH_INCLUDES) -lntdll -o $(BUILD_PATH)/test_library.exe

lib:
	$(MAKE) nix32_lib
	$(MAKE) nix64_lib
	$(MAKE) win32_lib
	$(MAKE) win64_lib

test:
	$(MAKE) nix32_test
	$(MAKE) nix64_test
	$(MAKE) win32_test
	$(MAKE) win64_test

clean:
	rm -rf $(BUILD_ROOT)
