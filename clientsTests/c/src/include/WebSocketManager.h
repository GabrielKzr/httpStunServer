#ifndef WEBSOCKETMANAGER_H
#define WEBSOCKETMANAGER_H

#include <cjson/cJSON.h>
#include <libwebsockets.h>

#define BUFFER_SIZE 2048

typedef struct {
    unsigned char uuid[33];
    char idToken[2048];
    int sent;  // Flag para evitar envio múltiplo
} session_data_t;

int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

int websocket_connect(const char* uuid, char* idToken);

#endif