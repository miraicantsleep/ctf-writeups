#include <stdio.h>
#include <limits.h>

int add(int x, int y) { return x + y; }

void main(){
	int n1, n2;
	printf("INT_MAX value: %d\n\nEnter 2 numbers: ", INT_MAX);
	scanf("%d %d", &n1, &n2);
	printf(n1 < 0 || n2 < 0 ? "\n[-] Negative values detected! Exiting..\n" : "\nThe sum of %d and %d is %d\n\n", n1, n2, add(n1, n2));
}			