#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdbool.h>


int main(){
    int N;
    // scanf("%d", &N);

    printf("Mallocing...\n");
    void *a = malloc(0x10);
    void *b = malloc(0x10);
    void *c = malloc(0x10);

    printf("a: %p\n", a);
    printf("b: %p\n", b);
    printf("c: %p\n", c);

    printf("\nFreeing...\n");

    free(a);
    free(b);
    free(c);

    printf("\nMallocing again...\n");

    void *d = malloc(0x10);
    void *e = malloc(0x10);
    void *f = malloc(0x10);

    printf("d: %p\n", d);
    printf("e: %p\n", e);
    printf("f: %p\n", f);
}