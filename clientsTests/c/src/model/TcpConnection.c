#include "TcpConnection.h"

int getUuidByServer(char* buffer, int port) {

    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Criar socket TCP
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        return 0;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return 0;
    }

    // Configurar endereço
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Aceita qualquer IP
    address.sin_port = htons(port);

    // Bind do socket
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 0;
    }

    // Escutar conexões
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        return 0;
    }

    printf("Aguardando conexão na porta %d...\n", port);

    // Aceitar conexão
    while((client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen))) {

        if (client_fd < 0) {
            perror("accept failed");
            close(server_fd);
            return 0;
        }

        printf("Cliente conectado!\n");

        // Ler os dados enviados pelo Dart
        int bytesRead = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            printf("JSON recebido: %s\n", buffer);
            close(client_fd);

            return 1;
        }
    }

    close(server_fd);

    return 0;
}
