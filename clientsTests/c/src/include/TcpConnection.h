#ifndef TCPCONNECTION_H
#define TCPCONNECTION_H

#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#define BUFFER_SIZE 2048

int getUuidByServer(char* buffer, int port);

#endif