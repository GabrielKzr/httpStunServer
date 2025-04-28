#include "src/include/WebSocketManager.h"
#include "src/include/StunHeaders.h"
#include "src/include/Utils.h"

int interrupted = 0;

static struct lws_protocols protocols[] = {
    {
        "my-protocol",
        callback_websockets,
        sizeof(session_data_t),  // sem per_session_data
        4096,
    },
    { NULL, NULL, 0, 0 } // fim da lista
};

int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("[client] Conectado!\n");
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {

            session_data_t *data = (session_data_t *)user;
            if (data->sent) break;

            size_t len;
            cJSON *json;
            StunHeader header;
            char *json_str;


            if (data->idToken[0] == '\0') { // caso não envie idToken, considera que já tem um uuid válido e reconhecido pelo servidor

                printf("uuid: %s\n", data->uuid);
                
                header = create_stun_request(data->uuid, 0x0005);
               
                json = stun_header_to_json(&header);
                if (!json) {
                    fprintf(stderr, "Falha ao criar JSON\n");
                    break;
                }

            } else {

                size_t uuid_len = strlen((char *)data->uuid);
                if (uuid_len != 32) {
                    fprintf(stderr, "UUID inválido: %s (comprimento: %zu, esperado: 32)\n",
                            data->uuid, uuid_len);
                    break;
                }

                printf("uuid: %s\n", data->uuid);
                printf("idToken: %s\n", data->idToken);

                StunHeader header = create_stun_request(data->uuid, 0x0001);
                
                json = stun_header_to_json(&header);
                if (!json) {
                    fprintf(stderr, "Falha ao criar JSON\n");
                    break;
                }
                cJSON_AddStringToObject(json, "auth_id", data->idToken);
            }


            // Serializa pra string
            json_str = cJSON_PrintUnformatted(json);
            if (!json_str) {
                fprintf(stderr, "cJSON_PrintUnformatted retornou NULL\n");
                cJSON_Delete(json);
                break;
            }

            len = strlen(json_str);
            printf("Tamanho calculado por strlen: %zu\n", len);

            // Verifica o tamanho antes de copiar
            if (len > BUFFER_SIZE) {
                fprintf(stderr, "JSON muito grande: %zu bytes\n", len);
                cJSON_Delete(json);
                free(json_str);
                break;
            }

            // Envia pela WebSocket
            unsigned char buf[LWS_PRE + BUFFER_SIZE];
            memcpy(&buf[LWS_PRE], json_str, len);

            // Envia os dados
            lws_write(wsi, &buf[LWS_PRE], len, LWS_WRITE_TEXT);

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

int websocket_connect(const char* uuid, char* idToken) {

    if (!uuid) {
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

    // printf("UUID: %s\n", uuid);
    // printf("DATA->UUID: %s\n", data->uuid);

    // Copia o idToken com terminador nulo
    if (idToken) {
        strncpy(data->idToken, idToken, sizeof(data->idToken) - 1);
        data->idToken[sizeof(data->idToken) - 1] = '\0'; // Garante terminador nulo
        // printf("DATA->idToken: %s\n", data->idToken);
    } else {
        data->idToken[0] = '\0'; // Deixa o array vazio
    }

    data->sent = 0;

    while (!interrupted) {
        lws_service(context, 100);
    }

    lws_context_destroy(context);

    return 1;
}