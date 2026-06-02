#include <stdio.h>

void
start_printer()
{
    (void)printf("Python taken over!\n");
}

void __attribute__((constructor)) test(void) {
    printf("Library loaded on dlopen()\n");
    start_printer();
}
