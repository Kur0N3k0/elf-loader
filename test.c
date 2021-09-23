#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

void func() {
    puts("helloworld func");
}

int main() {
    void *a = malloc(0x100);
    puts("helloworld");
    printf("wtf%d\n", 12);
    open("./test", O_RDONLY);
    return 0;
}