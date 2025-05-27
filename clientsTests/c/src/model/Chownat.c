#include "../include/Chownat.h"

sem_t bin_sem;

void chownat_disconnect(int chownat, struct sockaddr_in dst)
{
    printf("DEBUG: 9Attempting to disconnect\n");

    printf("DEBUG: Trying to disconnect...\n");
    sendto(chownat, "02\n", 3, 0, (struct sockaddr *)&dst, sizeof(dst));

    struct timeval timeout;
    timeout.tv_sec = 2;  // Timeout de 5 segundos
    timeout.tv_usec = 0;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(chownat, &readfds);

    while (true) {
        int ret = select(chownat + 1, &readfds, NULL, NULL, &timeout);

        if (ret == -1) {
            // Erro na função select
            perror("select");
            break;
        }
        else if (ret == 0) {
            // Timeout, nenhum dado recebido
            printf("DEBUG: Timeout reached, no message received.\n");
            break;
        }
        else {
            // Dados recebidos
            static char msg[3];
            recv(chownat, msg, 3, 0);
            if (strncmp(msg, "02\n", 3) == 0) {
                sendto(chownat, "02\n", 3, 0, (struct sockaddr *)&dst, sizeof(dst));
                break;
            }
        }
    }

    printf("DEBUG: REMOTE: Disconnected\n");
}

int chownat_start(char* remoteaddr, int remoteport)
{
    printf("DEBUG: Opening UDP socket on port %d\n", remoteport);
    printf("DEBUG: Opening TCP socket on port %d\n", localport);
    printf("DEBUG: Opening UDP socket on addr %s\n", remoteaddr);
    printf("DEBUG: Opening TCP socket on addr %s\n", localhost);
    
    // struct protoent *proto = getprotobyname("udp");
    // if (proto == NULL) {
    //     printf("ERROR: protocol udp not found.\n");
    //     exit(1);
    // }
    // printf("DEBUG: protocol UDP is number %d\n", proto->p_proto);
    int chownat = socket(AF_INET, SOCK_DGRAM, 0);
    if (chownat < 0) {
        printf("ERROR: socket %s\n", strerror(errno));
        exit(errno);
    }

    int optval = 1;
    if (setsockopt(chownat, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("ERROR: setsockopt(SO_REUSEADDR) failed");
        exit(errno);
    }

    struct sockaddr_in src = {};
    src.sin_family = AF_INET;
    src.sin_port = htons(remoteport);
    src.sin_addr.s_addr = INADDR_ANY;
    if (bind(chownat, (struct sockaddr*)&src, sizeof(src)) < 0) {
        printf("ERROR: bind %s\n", strerror(errno));
        exit(errno);
    }

    struct sockaddr_in dst = {};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(remoteport);
    dst.sin_addr.s_addr = inet_addr(remoteaddr);

    struct sockaddr_in local = {};
    local.sin_family = AF_INET;
    local.sin_port = htons(localport);
    local.sin_addr.s_addr = inet_addr(localhost);

    static char buffer[256][size];
    static size_t sizes[256];

    uint8_t id = 0;
    int sock = -1;
    int expected = 0;
    fd_set read_fds;
    while (true) {
        struct timeval timeout = {
            .tv_sec = 5,
            .tv_usec = 0
        };
        FD_ZERO(&read_fds);
        FD_SET(chownat, &read_fds);
        if (sock != -1)
            FD_SET(sock, &read_fds);
        int ready;
        while ((ready = select(max(chownat, sock) + 1, &read_fds, NULL, NULL, &timeout))) {
            if (ready < 0) {
                printf("ERROR: select %s\n", strerror(errno));
                exit(errno);
            }

            static char command[size];
            if (sock != -1 && FD_ISSET(sock, &read_fds)) {
                int nbytes = read(sock, command, size);
                // printf("DEBUG: TEM ALGO NO SOCK ---> %s\n", command);
                if (nbytes == 0) {
                    id = 0;
                    expected = 0;
                    // free(buffer);
                    // buffer = NULL;
                    printf("DEBUG: REMOTE: 4Attempting to disconnect\n");
                    chownat_disconnect(chownat, dst);

                    close(sock);
                    sock = -1;
                } else {
                    // Manter bufferizado
                    memcpy(&buffer[id], command, nbytes);
                    sizes[id] = nbytes;
                    
                    static char outbuf[size];
                    outbuf[0] = '0';
                    outbuf[1] = '9';
                    outbuf[2] = id;
                    id++;
                    memcpy(&outbuf[3], command, nbytes);
                    sendto(chownat, outbuf, nbytes+3, 0, (struct sockaddr*)&dst, sizeof(dst));
                }
            }
            

            if (FD_ISSET(chownat, &read_fds)) {
                // printf("DEBUG: TEM ALGO NO UDP ---> %s\n", command);

                // printf("DEBUG: received UDP packet\n");

                int recvd = recv(chownat, command, size, 0);
                //printf("DEBUG: UDP %s\n", command);
                if (recvd < 0) {
                    printf("ERROR: recv %s\n", strerror(errno));
                    exit(errno);
                }

                // printf("received: %x\n", command[1]);

                if (recvd == 0) {
                    id = 0;
                    expected = 0;
                    // free(buffer);
                    // buffer = NULL;
                    // printf("FODEU NAO TA IMPLEMENTADO ---> DEBUG: REMOTE: 5Attempting to disconnect\n");
                    chownat_disconnect(chownat, dst);
                    close(sock);
                    sock = -1;
                } 
                
                if (recvd < 3) {
                    // Ignore keep-alives
                    // printf("DEBUG: Ignoring keep-alive\n");
                    FD_ZERO(&read_fds);
                    FD_SET(chownat, &read_fds);
                    if (sock != -1)
                        FD_SET(sock, &read_fds);
                    continue;
                }

                // printf("Received %d bytes\n", recvd);
                // regex_t regex_cmd;
                // if (regcomp(&regex_cmd, "^09(.)", REG_EXTENDED | REG_NEWLINE) < 0) {
                //     printf("ERROR: regcomp %s\n", strerror(errno));
                //     exit(errno);
                // }

                if (strncmp(command, "01\n", 3) == 0) {
                    printf("DEBUG: REMOTE: 6Attempted to connect to us, initializing connection\n");

                    while (true) {
                        printf("DEBUG: Connecting...\n");
                        sendto(chownat, "03\n", 3, 0, (struct sockaddr *)&dst, sizeof(dst));
                        static char msg[4];
                        recv(chownat, msg, 3, 0);
                        msg[4] = 0;
                        if (strcmp(msg, "03\n") == 0) {
                            printf("DEBUG: REMOTE: Connection opened to remote end\n");
                            break;
                        } else {
                            printf("Received %x. Ignoring\n", msg[1]);
                        }
                    }

                    close(sock);
                    sock = socket(AF_INET, SOCK_STREAM, 0);
                    if (sock < 0) {
                        printf("ERROR: socket %s\n", strerror(errno));
                        exit(errno);
                    }
                    if (connect(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
                        printf("ERROR: connect %s\n", strerror(errno));
                        exit(errno);
                    }

                    printf("DEBUG: Connection to local daemon (port %d) opened\n", localport);
                } else if (strncmp(command, "02\n", 3) == 0) {
                    id = 0;
                    expected = 0;
                    // free(buffer);
                    // buffer = NULL;
                    printf("DEBUG: REMOTE: 7Attempting to disconnect\n");
                    chownat_disconnect(chownat, dst);
                    sendto(chownat, "02\n", 3, 0, (struct sockaddr*)&dst, sizeof(dst));

                    close(sock);
                    sock = -1;
                } else if (strncmp(command, "03\n", 3) == 0) {
                    printf("DEBUG: REMOTE: handshake\n");
                    sendto(chownat, "03\n", 3, 0, (struct sockaddr*)&dst, sizeof(dst));
                    FD_ZERO(&read_fds);
                    FD_SET(chownat, &read_fds);
                    if (sock != -1)
                        FD_SET(sock, &read_fds);
                    continue;
                } else if (strncmp(command, "08", 2) == 0) {
                    uint8_t got = command[2];
                    printf("DEBUG: Remote host needs packet %d, we're on %d\n", got, id);
                    
                    for (uint8_t i = got; i < id; i++) {
                        static char outbuf[size+3];
                        outbuf[0] = '0';
                        outbuf[1] = '9';
                        outbuf[2] = i;
                        memcpy(&outbuf[3], &buffer[i], sizes[i]);
                        printf("DEBUG: Retransmitting packet %d\n", i);
                        sendto(chownat, outbuf, sizes[i]+3, 0, (struct sockaddr*)&dst, sizeof(dst));
                    }

                } else if (strncmp(command, "09", 2) == 0) {
                    uint8_t got = command[2];
                    printf("DEBUG: Got packet %d, expected packet %d\n", got, expected);
                    if (got != expected) {
                        char msg[] = "080";
                        msg[2] = expected;
                        sendto(chownat, msg, sizeof(msg), 0, (struct sockaddr *)&dst, sizeof(dst));
                    } else {
                        printf("DEBUG: Received packet %d\n", got);
                        if (send(sock, &command[3], recvd - 3, 0) < 0) {
                            printf("ERROR: send %s\n", strerror(errno));
                            exit(errno);
                        }
                        // printf("DEBUG: MANDEI O SEND TCP %s\n", &command[3]);
                        expected++;
                        if(expected == 256) expected = 0;
                    }
                } else {
                    // printf("Command was %c%c\n", command[0], command[1]);
                    exit(1);
                }
            }
            FD_ZERO(&read_fds);
            FD_SET(chownat, &read_fds);
            if (sock != -1)
                FD_SET(sock, &read_fds);
        }

        int sent = sendto(chownat, "\0", 1, 0, (struct sockaddr *)&dst, sizeof(dst));
        if (sent < 0) {
            printf("ERROR: send %s\n", strerror(errno));
            exit(errno);
        }
        // printf("DEBUG: Sent keep-alive\n");
    }
}

void *holepunch(void* args) {
    struct chownat_data *data = (struct chownat_data *)args;
    char *remoteaddr = data->remoteaddr;
    int remoteport = data->remoteport;

    printf("DEBUG: Holepunch thread started with remoteaddr: %s, remoteport: %d\n", remoteaddr, remoteport);

    printf("DEBUG: Starting holepunch thread\n");

    sem_wait(&bin_sem);

    chownat_start(remoteaddr, remoteport);
    
    free (remoteaddr);
    
    free(args);

    sem_post(&bin_sem);

    return NULL;
}

void chownat_init() {
    sem_init(&bin_sem, 0, 1);
    printf("DEBUG: Chownat initialized\n");
}