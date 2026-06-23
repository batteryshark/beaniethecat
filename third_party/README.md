# Third-Party Dependencies

This directory separates dependency code and binary inputs from project-owned FLH source.

## Capstone

Capstone provides instruction decoding for overwrite sizing and trampoline relocation. The project currently vendors Capstone headers and platform-specific static libraries.

Tracked material:

- `capstone/include/capstone/*`
- `capstone/lib/*/libcapstone.a`
- `capstone/config.mk`

Keep Capstone as the default backend until a lighter decoder passes equivalent characterization tests.

## plthook

`plthook` provides ELF and PE import-table enumeration. The vendored files cite `https://github.com/kubo/plthook`.

Tracked material:

- `plthook/plthook.h`
- `plthook/plthook_elf.c`
- `plthook/plthook_win32.c`

Do not edit vendored `plthook` internals during layout refactors. Path and include updates are acceptable.

## ntdll.h

`ntdll.h` declares Windows native APIs used by the Windows platform implementation and tests. Treat it as vendored dependency material.
