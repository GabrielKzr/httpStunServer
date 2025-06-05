#define _XOPEN_SOURCE 700
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <linux/limits.h>
#include <libwebsockets.h>

#define EVENT_SIZE    (sizeof(struct inotify_event))
#define BUF_LEN       (1024 * (EVENT_SIZE + 16))

#define MAX_LINES     512
#define MAX_LINE_LEN  256

typedef struct {
    unsigned long timestamp;
    char mac[18];
    char ip[16];
    char hostname[64];
    char mac_ext[20];
} DeviceEntry;

typedef struct {
    const char *nomeArquivo;
    const char *diretorio;
    int *closed;
    int (*callback_function)(int, int, char[][MAX_LINE_LEN], void*);
    pthread_t* thread;
} WatcherArgs;

typedef struct {
    unsigned char uuid[33];
    char idToken[2049];
    WatcherArgs* watch;
} session_data_t;

int parseDeviceLine(const char *line, DeviceEntry *dev);
int readFile(const char *caminho, char lines[][MAX_LINE_LEN]);
int compareLines(char antes[][MAX_LINE_LEN], int n_antes, char agora[][MAX_LINE_LEN], int n_agora, char diff[][MAX_LINE_LEN], int *n_diff);
int fileWatcher(struct lws* wsi);
