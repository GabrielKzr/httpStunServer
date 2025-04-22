#include <unistd.h>
#include <arpa/inet.h>
#include <libwebsockets.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include "include/Utils.h"

#define PORT 3478
#define BUFFER_SIZE 1500

static int interrupted = 0;

typedef struct {
    unsigned char uuid[33];
    char idToken[2048];
    int sent;  // Flag para evitar envio múltiplo
} session_data_t;

int save_uuid_file(uint8_t *uuid_hex_str) {

    const char *filename = "uuid.txt";

    if (access(filename, F_OK) == 0) {
        printf("Arquivo %s já existe. Não será sobrescrito.\n", filename);
        return 0;
    }

    printf("Arquivo não tava aberto ainda\n");

    FILE *fp = fopen(filename, "wb");  // ainda em modo binário, mas salva string
    if (!fp) {
        perror("Erro ao abrir uuid.txt para escrita");
        return 0;
    }

    size_t len = strlen((char *)uuid_hex_str);
    if (len != 32) {
        fprintf(stderr, "UUID inválido, tamanho esperado: 32, obtido: %zu\n", len);
        fclose(fp);
        return 0;
    }

    // Debug: imprime os 32 caracteres
    printf("UUID em hexa (string): %s\n", uuid_hex_str);

    // Salva a string como está (32 bytes ASCII)
    size_t written = fwrite(uuid_hex_str, 1, 32, fp);
    fclose(fp);

    printf("VALORES SALVOSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");

    if (written != 32) {
        fprintf(stderr, "Erro: apenas %zu bytes foram escritos\n", written);
        return 0;
    }

    return 1;
}

static int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason,
                               void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("[client] Conectado!\n");
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            session_data_t *data = (session_data_t *)user;

            if (data->sent) break;

            size_t uuid_len = strlen((char *)data->uuid);
            if (uuid_len != 32) {
                fprintf(stderr, "UUID inválido: %s (comprimento: %zu, esperado: 32)\n",
                        data->uuid, uuid_len);
                break;
            }
            printf("DATA->UUID 2: %s\n", data->uuid);

            printf("data->idToken: %s\n", data->idToken);

            StunHeader header = create_stun_request(data->uuid, 0x0001);
            
            cJSON *json = stun_header_to_json(&header);
            if (!json) {
                fprintf(stderr, "Falha ao criar JSON\n");
                break;
            }
            cJSON_AddStringToObject(json, "auth_id", data->idToken);

            // Serializa pra string
            char *json_str = cJSON_PrintUnformatted(json);
            if (!json_str) {
                fprintf(stderr, "cJSON_PrintUnformatted retornou NULL\n");
                cJSON_Delete(json);
                break;
            }

            // Verifica o conteúdo de json_str
            printf("JSON string: %s\n", json_str);
            printf("Primeiros 50 bytes de json_str: ");
            for (int i = 0; i < 50 && json_str[i] != '\0'; i++) {
                printf("%02x ", (unsigned char)json_str[i]);
            }
            printf("\n");

            // Calcula o tamanho da string
            size_t len = strlen(json_str);
            printf("Tamanho calculado por strlen: %zu\n", len);

            // Verifica o tamanho antes de copiar
            if (len > 1500) {
                fprintf(stderr, "JSON muito grande: %zu bytes\n", len);
                cJSON_Delete(json);
                free(json_str);
                break;
            }

            // Envia pela WebSocket
            unsigned char buf[LWS_PRE + 2048];
            memcpy(&buf[LWS_PRE], json_str, len);

            // Envia os dados
            lws_write(wsi, &buf[LWS_PRE], len, LWS_WRITE_TEXT);

            // Libera memória
            cJSON_Delete(json);
            free(json_str);

            data->sent = 1;

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {

            char *msg = (char *)malloc(len + 1);
            if (!msg) exit(0);

            memcpy(msg, in, len);
            msg[len] = '\0'; // Garante terminação

            printf("[RECEBIDO] Mensagem do servidor:\n%s\n", msg);

            cJSON *json = cJSON_Parse((char*)in);
            if (!json) {
                fprintf(stderr, "Erro ao parsear JSON recebido!\n");
                free(msg);
                exit(0);
            }

            cJSON *status = cJSON_GetObjectItemCaseSensitive(json, "status");
            if (cJSON_IsString(status) && status->valuestring != NULL) {
                if (strcmp(status->valuestring, "success") == 0) {

                    cJSON *uuid = cJSON_GetObjectItemCaseSensitive(json, "message");
                    cJSON *authId = cJSON_GetObjectItemCaseSensitive(json, "auth_id");

                    if(uuid == NULL || authId == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    if(!save_uuid_file((uint8_t*)uuid->valuestring)) {                        
                        printf("Erro ao salvar uuid no arquivo");
                        exit(0);
                    } else {

                        StunHeader header = create_stun_request((uint8_t *)uuid->valuestring, 0x0004);

                        cJSON *json_send = stun_header_to_json(&header);
                        if (!json_send) {
                            fprintf(stderr, "Falha ao criar JSON\n");
                            exit(0);
                        }
                        cJSON_AddStringToObject(json_send, "auth_id", authId->valuestring);

                        char *json_str = cJSON_PrintUnformatted(json_send);
                        if (!json_str) {
                            fprintf(stderr, "cJSON_PrintUnformatted retornou NULL\n");
                            cJSON_Delete(json_send);
                            exit(0);
                        }

                        size_t len = strlen(json_str);

                        unsigned char buf[LWS_PRE + 2048];
                        memcpy(&buf[LWS_PRE], json_str, len);

                        lws_write(wsi, &buf[LWS_PRE], len, LWS_WRITE_TEXT);

                        free(json_str);
                        cJSON_Delete(json_send);
                    }

                } else if (strcmp(status->valuestring, "connected") == 0) {

                    printf("Processo de setup completo\n");

                } else if (strcmp(status->valuestring, "error") == 0) {
                    printf("Erro ao registrar UUID!\n");
                } else {
                    printf("Status desconhecido: %s\n", status->valuestring);
                }
            } else {
                printf("Campo 'status' não encontrado ou não é string.\n");
            }

            cJSON_Delete(json);
            free(msg);            

            break;
        }

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
        sizeof(session_data_t),  // sem per_session_data
        4096,
    },
    { NULL, NULL, 0, 0 } // fim da lista
};

int verifyUUIDreceived(const char* uuid, char* idToken) {
    if (!uuid || !idToken) {
        fprintf(stderr, "uuid ou idToken é NULL\n");
        return 0;
    }

    // Valida o comprimento do UUID
    size_t uuid_len = strlen(uuid);
    if (uuid_len != 32) {
        fprintf(stderr, "UUID inválido: %s (comprimento: %zu, esperado: 32)\n", uuid, uuid_len);
        return 0;
    }

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
    connect_info.ssl_connection = 0; // sem wss

    struct lws *wsi = lws_client_connect_via_info(&connect_info);
    if (!wsi) {
        fprintf(stderr, "Erro ao conectar ao servidor WebSocket\n");
        lws_context_destroy(context);
        return 0;
    }

    session_data_t *data = (session_data_t *)lws_wsi_user(wsi);
    if (!data) {
        fprintf(stderr, "session_data_t não inicializado\n");
        lws_context_destroy(context);
        return 0;
    }

    // Copia o UUID com terminador nulo
    strncpy((char *)data->uuid, uuid, 32);
    data->uuid[32] = '\0'; // Garante terminador nulo

    printf("UUID: %s\n", uuid);
    printf("DATA->UUID: %s\n", data->uuid);

    // Copia o idToken com terminador nulo
    strncpy(data->idToken, idToken, sizeof(data->idToken) - 1);
    data->idToken[sizeof(data->idToken) - 1] = '\0'; // Garante terminador nulo

    printf("DATA->idToken: %s\n", data->idToken);

    data->sent = 0;

    while (!interrupted) {
        lws_service(context, 100);
    }

    lws_context_destroy(context);

    return 1;
}

int main() {

    // Antes de usar:
    srand(time(NULL));  // Só uma vez no começo do programa

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

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
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
                cJSON_Delete(root);
                continue;
            }

            cJSON *uuidItem = cJSON_GetObjectItem(root, "uuid");
            const char* uuid_hex;

            if (cJSON_IsString(uuidItem) && uuidItem->valuestring != NULL) {
                uuid_hex = uuidItem->valuestring;
                if (strlen(uuid_hex) != 32) {
                    printf("Erro: UUID deve ser uma string de 32 caracteres hexadecimais\n");
                    cJSON_Delete(root); 
                    continue;
                }

                // Verifica se é um formato hexadecimal válido (apenas 0-9, a-f, A-F)
                for (int i = 0; i < 32; i++) {
                    char c = uuid_hex[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        printf("Erro: UUID contém caracteres não hexadecimais\n");
                        cJSON_Delete(root); 
                        continue;
                    }
                }

                // Imprime a string UUID para depuração
                printf("UUID (hex): %s\n", uuid_hex);

            } else {
                printf("Erro: UUID deve ser uma string\n");
                cJSON_Delete(root); 
                continue;
            }

            // Passa a string hexadecimal diretamente para verifyUUIDreceived
            if (!verifyUUIDreceived(uuid_hex, token_str)) {
                printf("Erro tentando salvar UUID\n");
            }

            cJSON_Delete(root);

            close(client_fd);
        }
    }

    close(server_fd);

    return 0;
}