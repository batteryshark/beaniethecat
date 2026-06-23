# Architecture

BeanieTheCat has four project-owned responsibilities:

- Public hook API: install and remove inline or import-table hooks.
- Hook entry layout: store original bytes, trampolines, chain stubs, and restore metadata.
- Instruction decoding: find safe overwrite lengths and relocate copied instructions.
- Platform services: resolve symbols, allocate executable memory, patch memory, and locate import slots.

Vendored dependencies are kept under `third_party/` and should not be edited unless the project deliberately forks them.

## Inline Hook Flow

`flh_inline_hook_byname` resolves a module symbol, then calls `flh_inline_hook`.

`flh_inline_hook` checks whether the target is already hooked. For a new hook it allocates a hook entry page near the target, writes the FLH magic marker, builds a jump from the original function to the entry, copies the original prologue bytes, sanitizes those copied bytes for trampoline execution, appends a jump back to the original function, patches the target prologue, and returns the trampoline.

Chained hooks replace the top-level hook and copy the previous top-level hook into the chain area. This preserves the ability for each redirect function to call the next trampoline.

## Import-Table Hook Flow

`flh_import_table_hook_byname` asks the import-table module to find the target import slot. It creates a hook entry, records the original function pointer and import slot address, marks the entry as import-table backed, patches the import slot to point at the hook entry, and returns a trampoline to the real function.

Import-table unhooking restores the saved function pointer to the saved import slot. The marker used to distinguish this path is private implementation detail.

## Instruction Decoding

The decoder backend currently uses Capstone. It calculates instruction-aligned overwrite sizes and rewrites copied relative call/jump instructions so trampoline execution resumes correctly. CET `ENDBR32` and `ENDBR64` instructions are replaced with NOPs in copied trampoline bytes.

Capstone is intentionally kept as the supported backend until a lighter decoder can match these behaviors under tests.

## Platform Boundary

Linux uses `dlopen`, `dlsym`, `mmap`, `mprotect`, `mincore`, and ELF import enumeration.

Windows uses native NT loader and virtual-memory APIs plus PE import enumeration.

Platform code owns OS-specific behavior only. Import-table traversal is separated from raw memory and symbol services so future platforms can add their own import-slot implementation without touching hook lifecycle code.

## Load-Bearing Weirdness

- The hook entry layout is byte-level ABI inside allocated executable pages.
- Nearby executable allocation matters for relative jump reachability.
- Chained hooks depend on fixed-size jump stubs.
- CET handling is intentionally conservative and should stay covered by decoder tests.
- Vendored static Capstone libraries are release inputs until a reproducible dependency build exists.
