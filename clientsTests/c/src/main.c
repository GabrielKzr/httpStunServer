#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <libwebsockets.h>
#include <signal.h>

#define PORT 3478
#define BUFFER_SIZE 1500

static int interrupted = 0;

static int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason,
                               void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("[client] Conectado!\n");
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            const char *msg = "Hello from client!";
            unsigned char buf[LWS_PRE + 256];
            size_t msg_len = strlen(msg);

            memcpy(&buf[LWS_PRE], msg, msg_len);
            lws_write(wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE:
            printf("[client] Recebido: %.*s\n", (int)len, (char *)in);
            interrupted = 1;
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "[client] Erro na conexão\n");
            interrupted = 1;
            break;

        case LWS_CALLBACK_CLOSED:
            printf("[client] Conexão fechada\n");
            interrupted = 1;
            break;

        default:
            break;
    }

    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "my-protocol",
        callback_websockets,
        0,  // sem per_session_data
        4096,
    },
    { NULL, NULL, 0, 0 } // fim da lista
};

int verifyUUIDreceived(unsigned char* uuid, char* idToken) {

    struct lws_context_creation_info context_info = {0};
    struct lws_client_connect_info connect_info = {0};
    struct lws_context *context;

    context_info.port = CONTEXT_PORT_NO_LISTEN;
    context_info.protocols = protocols;

    context = lws_create_context(&context_info);
    if (!context) {
        fprintf(stderr, "Erro ao criar contexto\n");
        return 0;
    }

    connect_info.context = context;
    connect_info.address = "localhost";
    connect_info.port = 18080;
    connect_info.path = "/ws";
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.protocol = protocols[0].name;
    connect_info.ssl_connection = 0;  // sem wss


    struct lws *wsi = lws_client_connect_via_info(&connect_info);
    if (!wsi) {
        fprintf(stderr, "Erro ao conectar ao servidor WebSocket\n");
        return 0;
    }

    while (!interrupted) {
        lws_service(context, 100);
    }

    lws_context_destroy(context);

    return 1;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE];
    int addrlen = sizeof(address);

    // Criar socket TCP
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Configurar endereço
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Aceita qualquer IP
    address.sin_port = htons(PORT);

    // Bind do socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Escutar conexões
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Aguardando conexão na porta %d...\n", PORT);

    // Aceitar conexão
    while((client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen))) {

        if (client_fd < 0) {
            perror("accept failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        printf("Cliente conectado!\n");

        // Ler os dados enviados pelo Dart
        int bytesRead = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("JSON recebido: %s\n", buffer);

            cJSON *root = cJSON_Parse(buffer);
            if (root == NULL) {
                printf("Erro ao fazer parse do JSON.\n");
                return 1;
            }

            cJSON *idToken = cJSON_GetObjectItemCaseSensitive(root, "idToken");
            char token_str[1300] = {0}; // zera tudo

            if (cJSON_IsString(idToken) && idToken->valuestring != NULL) {
                strncpy(token_str, idToken->valuestring, sizeof(token_str) - 1);
                printf("idToken: %s\n", token_str);
            } else {
                printf("idToken não encontrado ou inválido.\n");
            }

            cJSON *uuidArray = cJSON_GetObjectItem(root, "uuid");
            unsigned char uuid[16];
            int i = 0;

            if (cJSON_IsArray(uuidArray)) {
                cJSON *byte = NULL;
                cJSON_ArrayForEach(byte, uuidArray) {
                    if (i < 16 && cJSON_IsNumber(byte)) {
                        uuid[i++] = (unsigned char)byte->valueint;
                    }
                }

                printf("UUID (hex): ");
                for (int j = 0; j < i; j++) {
                    printf("%02x ", uuid[j]);
                }
                printf("\n");

                if (!verifyUUIDreceived(uuid, token_str)) {
                    printf("Erro tentando salvar UUID");
                }
            }

            cJSON_Delete(root);
        }
    }

    close(client_fd);
    close(server_fd);

    return 0;
}