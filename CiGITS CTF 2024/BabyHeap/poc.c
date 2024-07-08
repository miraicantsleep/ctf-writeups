#include <stdio.h>
#include <stdlib.h>

int main(){
    void *a = malloc(0x10);
    void *b = malloc(0x10);

    printf("a: %p\n", a);
    printf("b: %p\n", b);

    printf("Freeing a and b\n");
    free(a);
    free(b);

    void *c = malloc(0x10);
    void *d = malloc(0x10);

    printf("c: %p\n", c);
    printf("d: %p\n", d);

}