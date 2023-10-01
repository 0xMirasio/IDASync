#include <stdio.h>
#include "customlib.h"
// Define a custom structure for foo() to use

unsigned long long custom_lib_func(CustomStruct* struct_ptr, int* ptr, unsigned long long num) {
    printf("This is an example function in custom_lib.c\n");
    printf("a -> %d\n", struct_ptr->a);
    printf("b -> %c\n", struct_ptr->b);
    printf("c -> %p\n", struct_ptr->c);
    return *ptr + num;
}
