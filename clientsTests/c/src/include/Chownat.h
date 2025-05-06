#ifndef CHOWNAT_H
#define CHOWNAT_H

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <regex.h>

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <pthread.h>
#include <semaphore.h>

#define debug 0
#define localport 80
#define localhost "127.0.0.1"
#define size 1024

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

struct Session_Data {
    char remoteaddr[16];
    int remoteport;
};

extern sem_t bin_sem;

void chownat_disconnect(int chownat, struct sockaddr_in dst);
int chownat_start(char* remoteaddr, int remoteport);
void *holepunch(void *arg);
void chownat_init();

#endif