#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(){
    const char* flag = getenv("FLAG");
    if(flag == NULL) {
    	printf("Flag not found!\n");
    	exit(0);
    }
    printf("%s\n",flag);
}

void func(){
    char buf[040];
    while(1) {
        puts("Enter your info: \n");
        gets(buf);
        if(strlen(buf) < 31) {
            puts("Thank you for valid data!!!\n");
            break;
        }
        puts("My teacher says that's unsafe!\n");
    }
}

void main() {
    func();
}
