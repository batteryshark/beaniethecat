BUILD_ROOT := bin

LIB_PATH_32 := -L lib/x86_32
LIB_PATH_64 := -L lib/x86_64

FLH_COMPONENTS := src/flh/*.c -lcapstone -I include -I src

libs: libbeanie32 libbeanie64

libbeanie32:
	cc -m32 -shared -fPIC $(FLH_COMPONENTS) $(LIB_PATH_32) -o $(BUILD_ROOT)/$@.so

libbeanie64:
	cc -shared -fPIC $(FLH_COMPONENTS) $(LIB_PATH_64) -o $(BUILD_ROOT)/$@.so

test: test_linux_x86_32 test_linux_x86_64 test_lib_linux_x86_32 test_lib_linux_x86_64

test_linux_x86_32: 
	cc -m32 src/test/test.c $(FLH_COMPONENTS) $(LIB_PATH_32) -o $(BUILD_ROOT)/$@.elf

test_lib_linux_x86_32: libbeanie32
	cc -m32 src/test/test_library.c -ldl -o $(BUILD_ROOT)/$@.elf

test_lib_linux_x86_64: libbeanie64
	cc src/test/test_library.c -ldl -o $(BUILD_ROOT)/$@.elf

test_linux_x86_64:
	cc src/test/test.c  $(FLH_COMPONENTS) $(LIB_PATH_64) -o $(BUILD_ROOT)/$@.elf