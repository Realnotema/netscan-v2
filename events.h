#ifndef EVENTS_H
#define EVENTS_H

/* <--- Tehnique flags --->*/
#define HALF_CONNECT_TECHNIQUE 1
#define DATAGRAMM_TECHNIQUE 2

void event_handler(char *ip, int port, int technique);

#endif