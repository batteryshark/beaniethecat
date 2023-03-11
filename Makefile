TARGETS_LIB = nix32_lib nix64_lib win32_lib win64_lib
TARGETS_TEST = nix32_test nix64_test win32_test win64_test

.PHONY: $(TARGETS_LIB) $(TARGETS_TEST) clean help

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
endif

ifeq ($(findstring nix64,$(MAKECMDGOALS)),nix64)
  TARGET_PLATFORM := nix64
  TARGET_OS := linux
endif

ifeq ($(findstring win32,$(MAKECMDGOALS)),win32)
  TARGET_PLATFORM := win32
  TARGET_OS := windows
  FLH_FLAGS := $(FLH_FLAGS) -lntdll 
endif

ifeq ($(findstring win64,$(MAKECMDGOALS)),win64)
  TARGET_PLATFORM := win64
  TARGET_OS := windows
  FLH_FLAGS := $(FLH_FLAGS) -lntdll 
endif

BUILD_ROOT := ./build
BUILD_PATH := $(BUILD_ROOT)/$(TARGET_PLATFORM)
$(shell mkdir -p $(BUILD_PATH))

LIB_PATH := -L lib/$(TARGET_PLATFORM)
FLH_SRCS := src/flh/asm.c src/flh/flh.c src/flh/platform_$(TARGET_OS).c 
FLH_INCLUDES := -I include -I src

# Linux Targets
## -- 32bit
nix32_lib:
	cc -m32 -shared -fPIC $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/libflh.so
nix32_test: nix32_lib
	cc -m32 src/test/test.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.elf
	cc -m32 src/test/test_library.c -ldl -o $(BUILD_PATH)/test_library.elf
## -- 64bit
nix64_lib:
	cc -shared -fPIC $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/libflh.so
nix64_test:	nix64_lib
	cc src/test/test.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.elf
	cc src/test/test_library.c -ldl -o $(BUILD_PATH)/test_library.elf

# Windows Targets
## -- 32bit
win32_lib:
	i686-w64-mingw32-gcc -shared $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/flh.dll
win32_test: win32_lib
	i686-w64-mingw32-gcc src/test/test.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.exe
	i686-w64-mingw32-gcc src/test/test_library.c $(FLH_INCLUDES) -lntdll -o $(BUILD_PATH)/test_library.exe
## -- 64bit
win64_lib:
	x86_64-w64-mingw32-gcc -shared $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/flh.dll
win64_test: win64_lib
	x86_64-w64-mingw32-gcc src/test/test.c $(FLH_SRCS) $(FLH_INCLUDES) $(LIB_PATH) $(FLH_FLAGS) -o $(BUILD_PATH)/test.exe
	x86_64-w64-mingw32-gcc src/test/test_library.c $(FLH_INCLUDES) -lntdll -o $(BUILD_PATH)/test_library.exe

lib: $(TARGETS_LIB)
test: $(TARGETS_TEST)