#include <unistd.h>
#include <arpa/inet.h>
#include <libwebsockets.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include "include/Utils.h"
#include "include/WebSocketManager.h"

#define PORT 3478

int verifyUUID(const char* uuid, char* idToken) {
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

    websocket_connect(uuid, idToken);

    return 1;
}

int connectWithSavedUuid() {
    FILE *file = fopen("./uuid.txt", "rb"); // Abre em modo binário para leitura
    if (file == NULL) {
        printf("Arquivo não existe.\n");
        return 0; // Ou qualquer outro tratamento que quiser
    }
    // Move para o final para descobrir o tamanho
    fseek(file, 0, SEEK_END);
    long tamanho = ftell(file);
    rewind(file); // Volta para o começo para ler

    printf("Tamanho: %ld\n", tamanho);

    if (tamanho != 32) {
        printf("Arquivo existe, mas não tem 32 bytes (tem %ld bytes).\n", tamanho);
        fclose(file);
        exit(0);
    }

    // Se chegou aqui, tem exatamente 32 bytes
    unsigned char dados[32];
    size_t lidos = fread(dados, 1, 32, file);
    fclose(file);

    if (lidos != 32) {
        printf("Erro ao ler o arquivo.\n");
        exit(0);
    }  

    websocket_connect((char*)dados, NULL);

    return 1;
}

int getUuidByServer() {

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
            if (!verifyUUID(uuid_hex, token_str)) {
                printf("Erro tentando salvar UUID\n");
            }

            cJSON_Delete(root);

            close(client_fd);
        }
    }

    close(server_fd);

    return 0;
}

int main() {

    // Antes de usar:
    srand(time(NULL));  // Só uma vez no começo do programa

    if(!connectWithSavedUuid()) {
        getUuidByServer();  
    }

    return 0;
}