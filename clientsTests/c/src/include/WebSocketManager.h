#ifndef WEBSOCKETMANAGER_H
#define WEBSOCKETMANAGER_H

#include <cjson/cJSON.h>
#include <libwebsockets.h>
#include "list.h"
#include "FileChangeInterrupted.h"

#define BUFFER_SIZE 2048

#define NUM_THREADS 5

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

int callback_writeable(session_data_t* data, char* outBuffer);
int callback_receive(cJSON* in, char* outbuf, struct lws* wsi, session_data_t* data);
int callback_file_interrupt(int, int, char[][MAX_LINE_LEN], void*);

void notify_add(struct lws* wsi, char diff[][MAX_LINE_LEN], int len);
void notify_remove(struct lws* wsi, char diff[][MAX_LINE_LEN], int len);
void notify_alteration(struct lws* wsi, char diff[][MAX_LINE_LEN], int len);
void notify_send_request(struct lws* wsi, char diff[][MAX_LINE_LEN], int len, int type, const char* key);

void* callback_file_interrupt_thread(void* args);

int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

int websocket_connect(const char* uuid, char* idToken);

bool find_by_transaction_id(void* data, void* cmpval);

void print_stunHeader_tid(void* header);

#endif