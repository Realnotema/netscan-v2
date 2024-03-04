#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "methods.h"

void event_handler(char *ip, int port, int technique) {
    clock_t time_start= clock(); 
    if (scanTCP_SYN(ip, port) == SCAN_OPENED) {
        printf("%d/tcp\topen\n", port);
    } else printf("%d/tcp\tclosed\n", port);
    clock_t time_end = clock() - time_start;
    printf("Time: %.2f ms\n", (double)time_end / CLOCKS_PER_SEC * 1000);
}