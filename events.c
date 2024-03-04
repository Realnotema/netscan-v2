#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "methods.h"
#include "events.h"

void event_handler(char *ip, int port, int technique) {
    if (port != 0) {
        switch (technique){
            case HALF_CONNECT_TECHNIQUE:
                fprintf(stdout, "Trying scanning host %s\n\nPORT\tPROTO\tSTATUS\n", ip);
                clock_t time_start= clock(); 
                switch (scanTCP_SYN(ip, port)) {
                    case SCAN_CLOSED:
                        fprintf(stdout, "%d\tTCP\tclosed\n\n", port);
                        break;
                    case SCAN_OPENED:
                        fprintf(stdout, "%d\tTCP\topened\n\n", port);
                        break;
                }
                clock_t time_end = clock() - time_start;
                printf("Time left: %.2f sec.\n", (double)time_end / CLOCKS_PER_SEC * 100);
                break;
        }
    }
}