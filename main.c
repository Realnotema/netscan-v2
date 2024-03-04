#include <stdio.h>
#include <stdlib.h>
#include "methods.h"
#include <unistd.h>
#include "events.h"

void usage_help(char *argv[]) {
    fprintf(stdout, "Welcome to netscanner v2.0. - opensource scanner!\nUsage: %s {flags} {ip}\nYou need to combine flags! For example, if you choose TCP SYN technique ", argv[0]);
    fprintf(stdout, "\nFlags\tExplanation\n-h\tGet help page\n-p\tSelect concrete port\n-s\tTCP SYN technique\n-c\tTCP connect technique\n-u\tUDP technique\n");
}

void usage_flags(char *argv[]) {
    fprintf(stdout, "Usage:\n%s -p{other flag} {destination ip} {destination port}\n", argv[0]);
}

int main(int argc, char *argv[]) {
    int opt;
    int port = 0;
    while ((opt = getopt(argc, argv, "hpscu")) != -1) {
        switch (opt) {
            case 'h':
                usage_help(argv);
                break;
            case 'p':
                if (argc != 4) {
                    usage_flags(argv);
                    break;
                } 
                port = atoi(argv[3]);
                continue;
            case 's':
                if (argc < 3) {
                    usage_flags(argv);
                    break;
                } 
                event_handler(argv[2], port, HALF_CONNECT_TECHNIQUE);
                break;
            case 'c':
                printf("chose c\n");
                break;
        }
    }
    return 0;
}
