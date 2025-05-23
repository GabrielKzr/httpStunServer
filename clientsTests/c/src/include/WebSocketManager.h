#ifndef WEBSOCKETMANAGER_H
#define WEBSOCKETMANAGER_H

#include <cjson/cJSON.h>
#include <libwebsockets.h>
#include "list.h"

#define BUFFER_SIZE 2048

#define NUM_THREADS 5

typedef struct {
    unsigned char uuid[33];
    char idToken[2048];
} session_data_t;

typedef enum {
    STATUS_UNKNOWN,
    STATUS_BIND_SUCCESS,
    STATUS_CONNECTED,
    STATUS_EXCHANGE,
    STATUS_DISCONNECTED,
    STATUS_ABSENT,
    STATUS_ERROR
} StatusType;

StatusType get_status_type(const char *status);

size_t callback_writeable(session_data_t* data, char* outBuffer);
int callback_receive(cJSON* msg, char* outbuf);

int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

int websocket_connect(const char* uuid, char* idToken);

bool find_by_transaction_id(void* data, void* cmpval);

void print_stunHeader_tid(void* header);

#endif