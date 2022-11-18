#include <stdio.h>

#include "libs/libgost.h"

int main(int argc, char **argv) {
    if (GostCipher64_ControlECB())
        printf("ECB error!\n");
    if (GostCipher64_ControlCTR())
        printf("CTR error!\n");
    return 0;
}