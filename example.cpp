#include <stdio.h>
#include "loader.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *libPath[] = {
        "/lib/x86_64-linux-gnu/"
    };
    
    size_t size;
    char *image = LoadELF("./target", 0x00400000, &size, libPath, 1);

    char *argv[] = {
        "./target", (char *)Data, NULL
    };

    ((int (*)(int, char*[]))(image + 0x1231))(2, argv);

    finalize(image, size);
    return 0;
}