# BeanieTheCat Hooking Library
A filthy little hooker library for x86 32/64 named after the one and only Beanie.

![BeanieTheCat](./src/beanie.png)


## What Works
Linux and Windows Binaries of the x86 variety - 32 and 64bit supported.

# What needs testing and makefile entries
ARM64 Linux / MacOS

## How Does it Work?

Simple interface:

```c
// For hooking an address or module symbol target
void* flh_inline_hook_byname(const char* module_name, const char* function_name, void* redirect_function_address);
void* flh_inline_hook(void* target_address, void* redirect_function_address);

// For restoring original functionality
int flh_inline_unhook_byname(const char* module_name, const char* function_name);
int flh_inline_unhook(void* target_address);

// For pulling the hook table
void* flh_get_entry(void* target_address);
```

Essentially, specify a module name (or NULL for your process) and a function name along with your hook address and the hooker gets to work:

1. It supports both relative and absolute inline hooks with proper auto-padding thanks to capstone.

2. It creates a nearby page that supports multiple chained hooks seamlessly.

3. The hook function returns a "real_function" address you can use to call the orginal function from a supported trampoline - now with relative rebasing support!!!

4. Chain multiple hooks together by calling flh_inline_hook multiple times with various functions.

5. Supported handling to deal with CET calls (via not executing them in the trampoline, we'll see how reliable this is).

Unhooking is as easy as giving flh_inline_unhook the address of the function you want restored or "byname".


