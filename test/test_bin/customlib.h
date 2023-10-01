#ifndef CUSTOM_LIB_H
#define CUSTOM_LIB_H

typedef struct {
    int a;
    char b;
    void * c;
} CustomStruct;

unsigned long long custom_lib_func(CustomStruct* struct_ptr, int* ptr, unsigned long long num);

#endif /* CUSTOM_LIB_H */