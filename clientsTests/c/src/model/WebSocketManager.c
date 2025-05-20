#include "src/include/WebSocketManager.h"
#include "src/include/StunHeaders.h"
#include "src/include/Utils.h"
#include "src/include/Chownat.h"

list_t *list;

volatile int interrupted = 0;

static struct lws_protocols protocols[] = {
    {
        "",
        callback_websockets,
        sizeof(session_data_t),  // sem per_session_data
        4096,
    },
    { NULL, NULL, 0, 0 } // fim da lista
};

void sigint_handler(int sig) {
    interrupted = 1;
}

void print_stunHeader_tid(void* data) {

    char c[24];

    bytes_to_hex(((StunHeader*)data)->transaction_id, 12, c);

    printf("%s -> ", c);
}

int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("[client] Conectado!\n");

            list = (list_t *)malloc(sizeof(list_t));
            list_init(list);

            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {

            session_data_t *data = (session_data_t *)user;
            if (data->sent) break;

            size_t len;
            cJSON *json;
            StunHeader* header = malloc(sizeof(StunHeader));
            char *json_str;

            if (data->idToken[0] == '\0') { // caso não envie idToken, considera que já tem um uuid válido e reconhecido pelo servidor

                printf("uuid: %s\n", data->uuid);
                
                *header = create_stun_request(data->uuid, 0x0005);
               
                json = stun_header_to_json(header);
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

                *header = create_stun_request(data->uuid, 0x0001);
                
                json = stun_header_to_json(header);
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

            list_push_back(list, header);

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

                    cJSON *uuid = cJSON_GetObjectItemCaseSensitive(json, "uuid");
                    cJSON *authId = cJSON_GetObjectItemCaseSensitive(json, "auth_id");
                    cJSON *tid = cJSON_GetObjectItemCaseSensitive(json, "transaction_id");

                    if(uuid == NULL || authId == NULL || tid == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    list_entry_t *entry;
                    if((entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id)) == NULL) {
                        printf("Erro, transaction_id não encontrado na lista");
                        break;
                    } else {
                        printf("Transaction_id encontrado na lista\n");
                        free(entry->data); // limpando os dados alocados dinâmicamente, porque o remove não faz isso
                        list_remove(list, entry);
                    }

                    if(!save_uuid_file((uint8_t*)uuid->valuestring)) {                        
                        printf("Erro ao salvar uuid no arquivo");
                        exit(0);
                    } else {

                        StunHeader* header = malloc(sizeof(StunHeader));
                        *header = create_stun_request((uint8_t *)uuid->valuestring, 0x0004);

                        cJSON *json_send = stun_header_to_json(header);
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

                        list_push_back(list, header);

                        printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
                        list_print(list, print_stunHeader_tid);
                        printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");

                        free(json_str);
                        cJSON_Delete(json_send);
                    }

                } else if (strcmp(status->valuestring, "connected") == 0) {

                    cJSON *tid = cJSON_GetObjectItemCaseSensitive(json, "transaction_id");
                    
                    if(tid == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    list_entry_t *entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id);

                    if(entry == NULL) {
                        printf("Erro, transaction_id não encontrado na lista\n");
                        break;
                    } // não remove nesse caso, porque as repostas de troca de ip virão com esse transaction_id

                    printf("Processo de setup completo\n");

                } else if (strcmp(status->valuestring, "exchange") == 0) {
                    char remoteaddr[16] = {0};
                    int remoteport = 0;

                    cJSON *xor_port_item = cJSON_GetObjectItemCaseSensitive(json, "xor_port");
                    cJSON *xor_ip_item = cJSON_GetObjectItemCaseSensitive(json, "xor_ip");
                    cJSON *tid = cJSON_GetObjectItemCaseSensitive(json, "transaction_id");

                    if(tid == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    list_entry_t *entry;
                    if((entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id)) == NULL) {
                        printf("Erro, transaction_id não encontrado na lista");
                        break;
                    } 

                    if (!cJSON_IsNumber(xor_port_item) || !cJSON_IsString(xor_ip_item)) {
                        printf("Erro: xor_port ou xor_ip inválidos\n");
                        break;
                    }

                    // Des-XOR da porta
                    int xor_port = xor_port_item->valueint;
                    remoteport = xor_port ^ (MAGIC_COOKIE >> 16);

                    // Des-XOR do IP
                    uint8_t ip_parts[4];
                    if (sscanf(xor_ip_item->valuestring, "%hhu.%hhu.%hhu.%hhu", 
                            &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) != 4) {
                        printf("Erro: IP inválido\n");
                        break;
                    }

                    uint32_t xor_ip = (ip_parts[0] << 24) |
                                    (ip_parts[1] << 16) |
                                    (ip_parts[2] << 8)  |
                                    ip_parts[3];

                    uint32_t original_ip = xor_ip ^ MAGIC_COOKIE;

                    snprintf(remoteaddr, sizeof(remoteaddr), "%u.%u.%u.%u",
                        (original_ip >> 24) & 0xFF,
                        (original_ip >> 16) & 0xFF,
                        (original_ip >> 8)  & 0xFF,
                        original_ip & 0xFF
                    );

                    // DEBUG
                    printf("IP original: %s\n", remoteaddr);
                    printf("Porta original: %d\n", remoteport);

                    struct Session_Data *data = malloc(sizeof(struct Session_Data));
                    
                    data->remoteaddr = malloc(strlen(remoteaddr) + 1);
                    if (data->remoteaddr == NULL) {
                        printf("Erro ao alocar memória para remoteaddr\n");
                        free(data);
                        break;
                    }
                    strcpy(data->remoteaddr, remoteaddr);
                    data->remoteaddr[strlen(remoteaddr)] = '\0'; // Garante terminação
                    data->remoteport = remoteport;

                    pthread_t thread;

                    pthread_create(&thread, NULL, holepunch, data);

                    pthread_detach(thread);

                } else if (strcmp(status->valuestring, "disconnected") == 0) {
                    
                    printf("Roteador desconectado\n");

                    cJSON *tid = cJSON_GetObjectItemCaseSensitive(json, "transaction_id");

                    if(tid == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    list_entry_t *entry;
                    if((entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id)) == NULL) {
                        printf("Erro, transaction_id não encontrado na lista");
                        break;
                    } else {
                        printf("Transaction_id encontrado na lista\n");
                        free(entry->data); // limpando os dados alocados dinâmicamente, porque o remove não faz isso
                        list_remove(list, entry);
                    }   

                    remove_uuid_file();
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
                    interrupted = 1; // <- adicione isso
                    break;
                    
                }  else if (strcmp(status->valuestring, "absent") == 0) {

                    printf("UUID não encontrado no Firebase!\n");
                
                    cJSON *tid = cJSON_GetObjectItemCaseSensitive(json, "transaction_id");

                    if(tid == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    list_entry_t *entry;
                    if((entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id)) == NULL) {
                        printf("Erro, transaction_id não encontrado na lista");
                        break;
                    } else {
                        printf("Transaction_id encontrado na lista\n");
                        free(entry->data); // limpando os dados alocados dinâmicamente, porque o remove não faz isso
                        list_remove(list, entry);
                    }   

                    remove_uuid_file();
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
                    interrupted = 1; // <- adicione isso
                    break;

                }  else if (strcmp(status->valuestring, "error") == 0) {

                    cJSON *tid = cJSON_GetObjectItemCaseSensitive(json, "transaction_id");

                    if(tid == NULL) {
                        printf("Erro, json recebido inválido");
                        exit(0);
                    }

                    list_entry_t *entry;
                    if((entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id)) == NULL) {
                        printf("Erro, transaction_id não encontrado na lista");
                        break;
                    } else {
                        printf("Transaction_id encontrado na lista\n");
                        free(entry->data); // limpando os dados alocados dinâmicamente, porque o remove não faz isso
                        list_remove(list, entry);
                    }   

                    interrupted = 1; // <- adicione isso
                    printf("Erro ao registrar UUID!\n");
                    break; 

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
            printf("Conexão com o servidor não disponível\n");
            interrupted = 1;
            break;

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
        case LWS_CALLBACK_CLOSED:
            printf("[client] Conexão fechada\n");
            interrupted = 1;
            // acorda imediatamente o lws_service()
            lws_cancel_service(lws_get_context(wsi));
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("[client] close detectado, interrompendo loop\n");
            interrupted = 1;
            break;

        default:
            // printf("[client] Callback não tratado: %d\n", reason);
            break;
    }

    return 0;
}

bool find_by_transaction_id(void* data, void* cmpval) {
    if (data == NULL || cmpval == NULL)
        return false;

    StunHeader* header = (StunHeader*)data;
    uint8_t* target_id = (uint8_t*)cmpval;

    char c[24];

    bytes_to_hex(header->transaction_id, 12, c);

    return memcmp(c, target_id, 24) == 0;
}

int websocket_connect(const char* uuid, char* idToken) {

    chownat_init();
    interrupted = 0;

    struct lws_context_creation_info info;
    struct lws_client_connect_info connect_info;
    struct lws_context *context;

    // Validação de entrada
    if (!uuid) {
        lwsl_err("UUID é NULL\n");
        return 0;
    }

    size_t uuid_len = strlen(uuid);
    if (uuid_len != 32) {
        lwsl_err("UUID inválido: %s (comprimento: %zu, esperado: 32)\n", uuid, uuid_len);
        return 0;
    }

    // Configura o manipulador de sinal
    signal(SIGINT, sigint_handler);

    // Configuração do contexto
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    
    // Habilita logs detalhados (opcional)
    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

    // Cria o contexto
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("Erro ao criar contexto\n");
        return 0;
    }

    // Configuração da conexão
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = context;
    connect_info.address = "localhost";
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.port = 18080;
    connect_info.path = "/ws";
    connect_info.protocol = protocols[0].name;
    connect_info.pwsi = NULL;
    
    // Configurações SSL
    connect_info.ssl_connection = LCCSCF_USE_SSL |
                                 LCCSCF_ALLOW_SELFSIGNED |
                                 LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    
    // Estabelece a conexão
    struct lws *wsi = lws_client_connect_via_info(&connect_info);
    if (!wsi) {
        lwsl_err("Erro ao conectar ao servidor WebSocket\n");
        lws_context_destroy(context);
        return 0;
    }

    // Configura os dados da sessão
    session_data_t *data = (session_data_t *)lws_wsi_user(wsi);
    if (!data) {
        lwsl_err("session_data_t não inicializado\n");
        lws_context_destroy(context);
        return 0;
    }

    // Copia o UUID e idToken
    strncpy((char *)data->uuid, uuid, 32);
    data->uuid[32] = '\0';
    
    if (idToken) {
        strncpy(data->idToken, idToken, sizeof(data->idToken) - 1);
        data->idToken[sizeof(data->idToken) - 1] = '\0';
    } else {
        data->idToken[0] = '\0';
    }

    data->sent = 0;

    // Loop de serviço
    while (!interrupted) {
        lws_service(context, 0);
    }

    // Limpeza
    lws_context_destroy(context);
    if(list != NULL) {
        list_clear(list);
        free(list);
    }

    sleep(5);

    return 1;
}