#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#define PORT 3478
#define BUFFER_SIZE 1500

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
    client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_fd < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Cliente conectado!\n");

    // Ler os dados enviados pelo Dart
    int bytesRead = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0'; // Garantir que é uma string válida
        printf("JSON recebido: %s\n", buffer);

        // Aqui você pode usar sscanf, strtok ou uma lib como cJSON para parsear
        // Parse o JSON
        cJSON *root = cJSON_Parse(buffer);
        if (root == NULL) {
            printf("Erro ao fazer parse do JSON.\n");
            return 1;
        }

        // Extrair o idToken
        cJSON *idToken = cJSON_GetObjectItemCaseSensitive(root, "idToken");
        if (cJSON_IsString(idToken) && (idToken->valuestring != NULL)) {
            printf("idToken: %s\n", idToken->valuestring);
        } else {
            printf("idToken não encontrado ou inválido.\n");
        }

        cJSON *uuidArray = cJSON_GetObjectItem(root, "uuid");
        if (!cJSON_IsArray(uuidArray)) return 1;

        unsigned char uuid[16];
        int i = 0;

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
    }

    close(client_fd);
    close(server_fd);

    return 0;
}