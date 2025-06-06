#include <unistd.h>
#include <arpa/inet.h>
#include <libwebsockets.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include "include/Utils.h"
#include "include/WebSocketManager.h"
#include "include/TcpConnection.h"

#define PORT 3478

int connectWithSavedUuid() {

    char buffer[33];

    if(!getUuidFromFile(buffer, 32, "./uuid.txt")) return 0;
    buffer[32] = '\0'; 

    websocket_connect((char*)buffer, NULL);

    return 1;
}

int getServerInfo() {
    
    char buffer[BUFFER_SIZE];

    getUuidByServer(buffer, PORT);

    cJSON *root = cJSON_Parse(buffer);
    if (root == NULL) {
        printf("Erro ao fazer parse do JSON.\n");
        return 0;
    }

    cJSON *idToken = cJSON_GetObjectItemCaseSensitive(root, "idToken");
    char token_str[1300] = {0}; // zera tudo

    if (cJSON_IsString(idToken) && idToken->valuestring != NULL) {
        strncpy(token_str, idToken->valuestring, sizeof(token_str) - 1);
        printf("idToken: %s\n", token_str);
    } else {
        printf("idToken não encontrado ou inválido.\n");
        cJSON_Delete(root);
        return 0;
    }

    cJSON *uuidItem = cJSON_GetObjectItem(root, "uuid");
    const char* uuid_hex;

    if (cJSON_IsString(uuidItem) && uuidItem->valuestring != NULL) {
        uuid_hex = uuidItem->valuestring;
        if (strlen(uuid_hex) != 32) {
            printf("Erro: UUID deve ser uma string de 32 caracteres hexadecimais\n");
            cJSON_Delete(root); 
            return 0;
        }
    } else {
        printf("Erro: UUID deve ser uma string\n");
        cJSON_Delete(root); 
        return 0;
    }

    // Passa a string hexadecimal diretamente para verifyUUIDreceived
    websocket_connect(uuid_hex, token_str);

    cJSON_Delete(root);

    return 1;
}

int main() {

    // Antes de usar:
    srand(time(NULL));  // Só uma vez no começo do programa

    while (1)
    {
        if(!connectWithSavedUuid()) {
            if(!getServerInfo()) {
                continue;
            } 
        }
    }

    return 0;
}