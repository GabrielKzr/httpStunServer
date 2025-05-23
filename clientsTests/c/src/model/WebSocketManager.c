#include "../include/WebSocketManager.h"
#include "../include/StunHeaders.h"
#include "../include/Utils.h"
#include "../include/Chownat.h"

list_t *list;

volatile int interrupted = 0;

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

            list = (list_t *)malloc(sizeof(list_t));
            list_init(list);
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {

            session_data_t *data = (session_data_t *)user;

            unsigned char buf[LWS_PRE + BUFFER_SIZE];

            size_t len = callback_writeable(data, buf);

            if(len < 0) break;

            // Envia os dados
            lws_write(wsi, &buf[LWS_PRE], len, LWS_WRITE_TEXT);

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {

            char outBuffer[LWS_PRE + BUFFER_SIZE];

            cJSON *json = cJSON_Parse((char*)in); // só é permitido receber dados em formato de json
            if (!json) {
                fprintf(stderr, "Erro ao parsear JSON recebido!\n");
                break;
            }

            int len = callback_receive(json, outBuffer);

            if(len < 0) break;

            lws_write(wsi, &outBuffer[LWS_PRE], len, LWS_WRITE_TEXT);

            cJSON_Delete(json);


            cJSON *status = cJSON_GetObjectItemCaseSensitive(json, "status");
            if (cJSON_IsString(status) && status->valuestring != NULL) {
                if (strcmp(status->valuestring, "disconnected") == 0) {
                    
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
                        printf("Erro, transaction_id não encontrado na lista\n");
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
                        printf("Erro, json recebido inválido\n");
                        exit(0);
                    }

                    list_entry_t *entry;
                    if((entry = list_find(list, (void*)tid->valuestring, find_by_transaction_id)) == NULL) {
                        printf("Erro, transaction_id não encontrado na lista\n");
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

size_t callback_writeable(session_data_t* data, char* outBuffer) {

    size_t len;
    cJSON *json;
    StunHeader* header = malloc(sizeof(StunHeader));

    if (data->idToken[0] == '\0') { // caso não envie idToken, considera que já tem um uuid válido e reconhecido pelo servidor

        create_stun_request(header, data->uuid, 0x0005);
        
        stun_header_to_json(json, header);

    } else {

        create_stun_request(header, data->uuid, 0x0001);
        
        stun_header_to_json(json, header);

        cJSON_AddStringToObject(json, "auth_id", data->idToken);
    }

    // Serializa pra string
    char* json_str = cJSON_PrintUnformatted(json);
    if (!json_str) {
        fprintf(stderr, "cJSON_PrintUnformatted retornou NULL\n");
        cJSON_Delete(json);
        free(json_str);
        return -1;
    }

    // Verifica o tamanho antes de copiar
    len = strlen(json_str);

    // Envia pela WebSocket
    memcpy(&outBuffer[LWS_PRE], json_str, len);

    cJSON_Delete(json);
    free(json_str);

    // SALVA O HEADER NA LISTA
    list_push_back(list, header);

    return len;
}

int callback_receive(cJSON* msg, char* outbuf) {
    printf("[RECEBIDO] Mensagem do servidor:\n%s\n", msg->valuestring);

    cJSON* status = cJSON_GetObjectItemCaseSensitive(msg, "status");
    if(!cJSON_IsString(status) || status->valuestring == NULL) {
        return -1;
    }

    StatusType statusType = get_status_type(status->valuestring);

    switch (statusType)
    {
    case STATUS_BIND_SUCCESS: {
 
        // TRATAMENTO DOS VALORES RECEBIDOS

        cJSON *uuid = cJSON_GetObjectItemCaseSensitive(msg, "uuid");
        cJSON *authId = cJSON_GetObjectItemCaseSensitive(msg, "auth_id");
        cJSON *tid = cJSON_GetObjectItemCaseSensitive(msg, "transaction_id");

        if(uuid == NULL || authId == NULL || tid == NULL) {
            printf("Erro, json recebido inválido\n");
            return -1;
        }

        char* tid_s = tid->valuestring;
        list_entry_t *entry = list_find(list, tid_s, find_by_transaction_id);

        if(entry == NULL || entry->data == NULL) {
            printf("Entry ou Data está nulo\n");
            return -1;
        }

        free(entry->data);
        list_remove(list, entry);

        uint8_t* uuid_u = (uint8_t *)uuid->valuestring;
        int ret = save_uuid_file(uuid_u);

        if(!ret) return -1;

        // CONFIRMAÇÃO DOS DADOS APÓS SALVAR UUID

        StunHeader* header = malloc(sizeof(StunHeader));
        cJSON* json;

        create_stun_request(header, uuid_u, 0x0004);
        stun_header_to_json(json, header);

        char* authId_s = authId->valuestring;
        cJSON_AddStringToObject(json, "auth_id", authId_s); // salva o authID, porque precisa da identificação no servidor

        char* json_str = cJSON_PrintUnformatted(json);
        if (!json_str) {
            fprintf(stderr, "cJSON_PrintUnformatted retornou NULL\n");
            cJSON_Delete(json);
            free(json_str);
            return -1;
        }

        size_t len = strlen(json_str);
        memcpy(&outbuf[LWS_PRE], json_str, len);

        list_push_back(list, header);

        free(json_str);
        cJSON_Delete(json);

        return len;
    }
       
    case STATUS_CONNECTED: {
        
        cJSON *tid = cJSON_GetObjectItemCaseSensitive(msg, "transaction_id");                   
        if(tid == NULL) return -1;

        char* tid_s = tid->valuestring;
        list_entry_t *entry = list_find(list, tid_s, find_by_transaction_id);

        if(entry == NULL) {
            printf("Erro, transaction_id não encontrado na lista\n");
            break;
        }

        printf("SETUP COMPLETO\n");

        break;

    }

    case STATUS_EXCHANGE: {

        char remoteaddr[16] = {0};
        int remoteport = 0;

        cJSON *xor_port_item = cJSON_GetObjectItemCaseSensitive(msg, "xor_port");
        cJSON *xor_ip_item = cJSON_GetObjectItemCaseSensitive(msg, "xor_ip");
        cJSON *tid = cJSON_GetObjectItemCaseSensitive(msg, "transaction_id");

        if(tid == NULL || xor_ip_item == NULL || xor_port_item == NULL) {
            printf("Erro, json recebido inválido");
            return -1;
        }

        char* tid_s = tid->valuestring;
        list_entry_t* entry = list_find(list, tid_s, find_by_transaction_id);

        if (!cJSON_IsNumber(xor_port_item) || !cJSON_IsString(xor_ip_item)) {
            printf("Erro: xor_port ou xor_ip inválidos\n");
            return -1;
        }

        remoteport = unxor_port(xor_port_item->valueint);
        unxor_ip(xor_ip_item->valuestring, remoteaddr);
        
        printf("remoteport: %d\n", remoteport);
        printf("remoteaddr: %s\n", remoteaddr);

        // ----------------- INICIANDO A SESSÃO DO CHOWNAT

        struct chownat_data *data = malloc(sizeof(struct chownat_data));
        
        data->remoteaddr = malloc(strlen(remoteaddr) + 1);
        strcpy(data->remoteaddr, remoteaddr);
        data->remoteaddr[strlen(remoteaddr)] = '\0'; // Garante terminação
        data->remoteport = remoteport;

        pthread_t thread;

        pthread_create(&thread, NULL, holepunch, data);

        pthread_detach(thread);

        break;

    }

    case STATUS_DISCONNECTED:
    case STATUS_ABSENT: {
        
        cJSON *tid = cJSON_GetObjectItemCaseSensitive(msg, "transaction_id");

        if(tid == NULL) return -1;

        char* tid_s = tid->valuestring;
        list_entry_t* entry =  list_find(list, tid_s, find_by_transaction_id);

        if(entry == NULL) {
            printf("Erro, transaction_id não encontrado na lista");
            return -1;
        }

        free(entry->data);
        list_remove(list, entry);

        int ret = remove_uuid_file();
        
        if(ret < 0) return -1;

        return 0; 
    }

    case STATUS_ERROR: {

        cJSON *tid = cJSON_GetObjectItemCaseSensitive(msg, "transaction_id");

        if(tid == NULL) return -1;

        char* tid_s = tid->valuestring;
        list_entry_t* entry =  list_find(list, tid_s, find_by_transaction_id);

        if(entry == NULL) {
            printf("Erro, transaction_id não encontrado na lista");
            return -1;
        }

        free(entry->data);
        list_remove(list, entry);

        return -1;
    }

    case STATUS_UNKNOWN:
    default:
        printf("Status desconhecido: %s\n", status->valuestring);
        break;
    }
}

int websocket_connect(const char* uuid, char* idToken) {

    struct lws_context_creation_info context_info = {0};
    struct lws_client_connect_info connect_info = {0};
    struct lws_context *context;
    size_t uuid_len;
    struct lws *wsi;
    session_data_t *data;

    chownat_init();

    interrupted = 0;

    if (!uuid) {
        fprintf(stderr, "uuid ou idToken é NULL\n");
        return 0;
    }

    uuid_len = strlen(uuid);
    if (uuid_len != 32) {
        fprintf(stderr, "UUID inválido: %s (comprimento: %zu, esperado: 32)\n", uuid, uuid_len);
        return 0;
    }

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

    wsi = lws_client_connect_via_info(&connect_info);
    if (!wsi) {
        fprintf(stderr, "Erro ao conectar ao servidor WebSocket\n");
        lws_context_destroy(context);
        return 0;
    }

    data = (session_data_t *)lws_wsi_user(wsi);
    if (!data) {
        fprintf(stderr, "session_data_t não inicializado\n");
        lws_context_destroy(context);
        return 0;
    }

    strncpy((char *)data->uuid, uuid, 32);
    data->uuid[32] = '\0'; 

    if (idToken) {
        strncpy(data->idToken, idToken, sizeof(data->idToken) - 1);
        data->idToken[sizeof(data->idToken) - 1] = '\0'; 
    } else {
        data->idToken[0] = '\0'; 
    }

    while (!interrupted) {
        lws_service(context, 100);
    }

    lws_context_destroy(context);

    if(list != NULL) {
        list_clear(list);
        free(list);
    }

    sleep(5);

    return 1;
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

void print_stunHeader_tid(void* data) {

    char c[24];

    bytes_to_hex(((StunHeader*)data)->transaction_id, 12, c);

    printf("%s -> ", c);
}

StatusType get_status_type(const char *status) {
    if (strcmp(status, "success") == 0) return STATUS_BIND_SUCCESS;
    if (strcmp(status, "connected") == 0) return STATUS_CONNECTED;
    if (strcmp(status, "exchange") == 0) return STATUS_EXCHANGE;
    if (strcmp(status, "disconnected") == 0) return STATUS_DISCONNECTED;
    if (strcmp(status, "absent") == 0) return STATUS_ABSENT;
    if (strcmp(status, "error") == 0) return STATUS_ERROR;
    return STATUS_UNKNOWN;
}