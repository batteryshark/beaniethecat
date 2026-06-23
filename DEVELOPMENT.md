# Development

BeanieTheCat is a process-memory patching library. Run tests only in disposable local processes that you control. The tests hook `system`, patch executable memory, and temporarily relax page protections.

## Toolchains

Supported source targets:

- Linux x86 and x86-64 with POSIX `make`, `cc`, and `libdl`.
- Windows x86 and x86-64 with MinGW cross compilers.

Known local verification path:

```sh
wsl -d Ubuntu --cd /mnt/g/CodeTmp/beaniethecat -- make nix64_test
wsl -d Ubuntu --cd /mnt/g/CodeTmp/beaniethecat -- ./build/nix64/test.elf
wsl -d Ubuntu --cd /mnt/g/CodeTmp/beaniethecat -- ./build/nix64/test_iat.elf
```

The dynamic-library test expects to run from the platform build directory so `./libflh.so` or `flh.dll` resolves beside the executable:

```sh
wsl -d Ubuntu --cd /mnt/g/CodeTmp/beaniethecat/build/nix64 -- ./test_library.elf
```

MSYS2 is expected at `C:\msys64` for Windows work. Before Windows validation, confirm `make` or `mingw32-make` is installed and that the MinGW compilers are on PATH.

## Build Targets

```sh
make nix64_test
make nix64_lib
make win64_lib
make clean
```

`make lib` and `make test` invoke all platform-specific targets. Prefer one explicit target during refactors so failures stay narrow.

## Safety Rules

- Do not run tests inside a process that has valuable state.
- Do not change trampoline byte layout without passing characterization tests.
- Do not replace Capstone until decoder tests cover instruction sizing, CET `ENDBR`, relative call/jump relocation, and malformed bytes.
- Treat `build/` as disposable generated output.
