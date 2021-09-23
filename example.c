#include <stdio.h>
#include "loader.h"

int main(int argc, char *argv[]) {
    if(argc != 2) {
        return 0;
    }

    char *input = argv[1];

    char *libPath[] = {
        "/lib/x86_64-linux-gnu/"
    };

    size_t size;
    char *image = LoadELF(input, 0x00400000, &size, libPath, 1);

    ((void (*)())(image + 0x1196))();

    munmap(image, size);

    return 0;
}