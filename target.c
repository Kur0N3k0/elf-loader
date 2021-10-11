#include <stdio.h>
#include <string.h>

void vuln(char *input) {
    char buf[128] = { 0, };
    strcpy(buf, input);
}

int main(int argc, char *argv[]) {
    vuln(argv[1]);
    return 0;
}