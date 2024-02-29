#include <stdio.h>
#include <stdlib.h>
#include "methods.h"

/* <--- Tehnique flags --->*/
#define CONNECT_TEHNIQUE 1
#define HALF_CONNECT_TECHNIQUE 2
#define DATAGRAMM_TECHNIQUE 3

int main(int argc, char *argv[]) {
    clock_t time_start= clock(); 
    if (scanTCP_SYN("45.33.32.156", 135) == SCAN_OPENED) {
        printf("%d/tcp\topen\n", 22);
    }
    clock_t time_end = clock() - time_start;
    printf("Time: %f sec.\n", (double)time_end / CLOCKS_PER_SEC);
    return 0;
}
