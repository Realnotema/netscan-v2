#include <stdio.h>
#include <stdlib.h>
#include "methods.h"

/* <--- Tehnique flags --->*/
#define CONNECT_TEHNIQUE 1
#define HALF_CONNECT_TECHNIQUE 2
#define DATAGRAMM_TECHNIQUE 3

int main(int argc, char *argv[]) {
    if (scanTCP_SYN("85.143.113.117", 2202) == SCAN_OPENED) {
        printf("opened\n");
    } else printf("closed\n");
}
