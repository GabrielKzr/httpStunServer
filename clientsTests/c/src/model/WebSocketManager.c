#include "../include/WebSocketManager.h"
#include "../include/StunHeaders.h"
#include "../include/Utils.h"
#include "../include/Chownat.h"

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

int callback_websockets(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("[client] Conectado!\n");

            list = (list_t *)malloc(sizeof(list_t));
            if (list == NULL) {
                printf("*********** LISTA TA NULA PORRA ************");
            }
            list_init(list);
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE: {

            session_data_t *data = (session_data_t *)user;

            char *buf = malloc(LWS_PRE + BUFFER_SIZE);

            int len = callback_writeable(data, buf);

            if(len < 0) {
                free(buf);
                break;
            }

            // Envia os dados
            lws_write(wsi, (unsigned char*)&buf[LWS_PRE], len, LWS_WRITE_TEXT);

            free(buf);

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {

            session_data_t *data = (session_data_t *)user;
            static char outBuffer [LWS_PRE + BUFFER_SIZE];

            cJSON *json = cJSON_Parse((char*)in); // só é permitido receber dados em formato de json
            if (!json) {
                fprintf(stderr, "Erro ao parsear JSON recebido!\n");
                break;
            }

            int len = callback_receive(json, outBuffer, wsi, data);

            cJSON_Delete(json);

            if(len < 0) 
                break;

            if(len == 0) {
                interrupted = 1;
                break;
            }

            lws_write(wsi, (unsigned char*)&outBuffer[LWS_PRE], len, LWS_WRITE_TEXT);

            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("Conexão com o servidor não disponível\n");
            interrupted = 1;
            break;

        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:

            session_data_t *data = (session_data_t *)user;
            printf("[client] Servidor fechou conexão\n");
            interrupted = 1;
            lws_cancel_service(lws_get_context(wsi));

            if(in == NULL) return -1;

            char *msg = malloc(len-2);
            if (msg) {
                memcpy(msg, (char *)in +2, len-2);
                msg[len-2] = '\0'; // Garante terminação nula

                // Exibe o código de status e a mensagem

                printf("Mensagem de fechamento: %s\n", msg);
            }

            cJSON *json = cJSON_Parse(msg); // só é permitido receber dados em formato de json
            if (!json) {
                fprintf(stderr, "Erro ao parsear JSON recebido!\n");
                free(msg);
                break;
            }
            
            char buf[32] = {0};
            int len = callback_receive(json, buf, wsi, data);

            free(msg);

            if(len) {
                printf("Resposta do servidor incoerente\n");
                return -1;
            }
            
            break;

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

int callback_writeable(session_data_t* data, char* outBuffer) {

    size_t len = 0;
    cJSON *json = cJSON_CreateObject();
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
        interrupted = 1;
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

int callback_receive(cJSON* msg, char* outbuf, struct lws* wsi, session_data_t* data) {

    char* json_str = cJSON_PrintUnformatted(msg);
    if(json_str) {
        printf("[RECEBIDO] Mensagem do servidor:\n%s\n", json_str);
        free(json_str);
    }

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

        char *uuid_u = uuid->valuestring;
        int ret = save_uuid_file(uuid_u);

        if(!ret) return -1;

        StunHeader* header = malloc(sizeof(StunHeader));
        cJSON* json = cJSON_CreateObject();

        create_stun_request(header, (unsigned char *)uuid_u, 0x0004);
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
            return -1;
        }

        printf("SETUP COMPLETO\n"); // AQUI É ONDE REALMENTE PODE CONSIDERAR QUE O ROTEADOR ESTÁ CONECTADO

        if (pthread_create(data->watch->thread, NULL, callback_file_interrupt_thread, wsi) != 0) {
            perror("Erro ao criar a thread");
            return 1;
        }

        printf("CRIEI A THREAD\n");

        return -2; // -2, porque < 0 ele só da break e não escreve nada, mas não é um erro, se precisar tratar, é possível diferenciar
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
        if(entry == NULL) {
            printf("Transaction id não encontrado\n");
            return -1;
        }

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

        return -2; // -2, porque < 0 ele só da break e não escreve nada, mas não é um erro, se precisar tratar, é possível diferenciar
    }

    case STATUS_DISCONNECTED: // na verdade é "removed"
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

        printf("Arquivo de uuid removido\n");
        
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
        return -1;
    }
}

void* callback_file_interrupt_thread(void *args) {
    struct lws* wsi = (struct lws*) args;

    printf("CALLBACK THREAD\n");

    fileWatcher(wsi);

    return NULL;
}

int callback_file_interrupt(int type, int n_diff, char diff[][MAX_LINE_LEN], void* wsi) {
    
    struct lws* _wsi = (struct lws*)wsi;

    switch (type)
    {
    case 0:
        printf("Não ouve alterações\n");
        break;

    case 1:
        notify_add(_wsi, diff, n_diff);
        break;
    
    case 2:
        notify_remove(_wsi, diff, n_diff);
        break;

    case 3:
        notify_alteration(_wsi, diff, n_diff);
        break;

    default:
        
        printf("Tipo recebido não conhecido\n");
        break;
    }

    return 1;
}

void notify_send_request(struct lws* wsi, char diff[][MAX_LINE_LEN], int len, int type, const char* key) {
    session_data_t* data = (session_data_t *)lws_wsi_user(wsi);
    char *buf = malloc(LWS_PRE + BUFFER_SIZE);
    StunHeader* header = malloc(sizeof(StunHeader));
    cJSON* json = cJSON_CreateObject();

    create_stun_request(header, data->uuid, type);
    stun_header_to_json(json, header);

    cJSON *diff_array = cJSON_CreateArray();

    for (int i = 0; i < len; i++) {
        cJSON *item = cJSON_CreateString(diff[i]);
        cJSON_AddItemToArray(diff_array, item);
    }

    cJSON_AddItemToObject(json, key, diff_array);

    char *json_str = cJSON_PrintUnformatted(json);
    size_t tam = strlen(json_str);

    printf("json_str: %s\n", json_str);

    memcpy(&buf[LWS_PRE], json_str, tam);

    lws_write(wsi, (unsigned char*)&buf[LWS_PRE], tam, LWS_WRITE_TEXT);

    // FALTA ADICIONAR O STUNHEADER/TRANSACTION_ID NA LISTA

    free(header);
    free(buf);
    free(json_str);
    cJSON_Delete(json);
}

void notify_add(struct lws* wsi, char diff[][MAX_LINE_LEN], int len) {

    printf("Enviando requisição de add para o servidor\n");

    notify_send_request(wsi, diff, len, 0x0008, "notify_add");
}

void notify_remove(struct lws* wsi, char diff[][MAX_LINE_LEN], int len) {
    printf("Enviando requisição de remove para o servidor\n");

    notify_send_request(wsi, diff, len, 0x0008, "notify_remove");
}

void notify_alteration(struct lws* wsi, char diff[][MAX_LINE_LEN], int len) {
    printf("Enviando requisição de alteração para o servidor\n");

    notify_send_request(wsi, diff, len, 0x0008, "notify_alteration");
}

int websocket_connect(const char* uuid, char* idToken) {

    struct lws_context_creation_info context_info = {0};
    struct lws_client_connect_info connect_info = {0};
    struct lws_context *context;
    struct lws *wsi;
    session_data_t *data;
    int closed = 0;

    chownat_init();

    interrupted = 0;

    memset(&context_info, 0, sizeof(context_info));
    context_info.port = CONTEXT_PORT_NO_LISTEN;
    context_info.protocols = protocols;
    context_info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

    context = lws_create_context(&context_info);
    if (!context) {
        fprintf(stderr, "Erro ao criar contexto\n");
        return 0;
    }

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

    memset(data, 0, sizeof(session_data_t));

    strncpy((char *)data->uuid, uuid, 32);
    data->uuid[32] = '\0'; 

    if (idToken) {
        strncpy(data->idToken, idToken, sizeof(data->idToken) - 1);
        data->idToken[sizeof(data->idToken) - 1] = '\0'; 
    } else {
        data->idToken[0] = '\0'; 
    }

    WatcherArgs* watcher = malloc(sizeof(WatcherArgs));
    watcher->nomeArquivo = "teste.txt";
    watcher->diretorio = ".";
    watcher->callback_function = callback_file_interrupt;
    watcher->closed = &closed;
    watcher->thread = malloc(sizeof(pthread_t));

    data->watch = watcher;

    while (!interrupted) {
        lws_service(context, 100);
    }

    lws_context_destroy(context);

    if(list != NULL) {
        printf("************* LIMPEI A LISTAAAAAAAAA **********************\n");
        list_clear(list);
        free(list);
        list = NULL;
    }

    closed = 1;

    sleep(5);

    pthread_cancel(*watcher->thread); // destrói a thread
    free(watcher->thread);
    free(watcher);

    return 1;
}

bool find_by_transaction_id(void* data, void* cmpval) {
    if (data == NULL || cmpval == NULL)
        return false;

    StunHeader* header = (StunHeader*)data;
    char* target_id = (char*)cmpval; // SE CASTAR PARA UINT8_T ELE CORROMPE A MEMÓRIA, NÃO FAÇO IDEIA PORQUE, COMPILADOR TA QUEBRADO

    return memcmp(header->transaction_id, target_id, 24) == 0;
}

void print_stunHeader_tid(void* data) {

    if (data == NULL)
        return;

    printf("%s -> ", ((StunHeader*)data)->transaction_id);
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