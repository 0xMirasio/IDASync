#include <stdio.h>
#include "customlib.h"

int main() {
    
    int x = 10;
    CustomStruct my_struct = { 42, 'P' , &x};
    int* ptr = &x; 
    unsigned long long num = 123456789012345;
    unsigned long long ret = custom_lib_func(&my_struct, ptr, num);
    printf("ret = %lld\n", ret);
    return 0;
}