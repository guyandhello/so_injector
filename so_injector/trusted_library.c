#include <stdio.h>
#include <dlfcn.h>

int printf(const char *format, ...)
{
    void * libc_handle = NULL;
    int (*printf_symbol)(const char *) = NULL;

    libc_handle = dlopen("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY);
    if (NULL == libc_handle)
    {
        return -1;
    }

    printf_symbol = dlsym(libc_handle, "printf");
    printf_symbol("Hello EVIL world!\n");
    return 1;
}
