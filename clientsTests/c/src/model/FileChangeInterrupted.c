#include "../include/FileChangeInterrupted.h"

int parseDeviceLine(const char *line, DeviceEntry *dev) {
    return sscanf(line, "%lu %17s %15s %63s %19s",
                 &dev->timestamp, dev->mac, dev->ip,
                 dev->hostname, dev->mac_ext) == 5;
}

int readFile(const char *caminho, char lines[][MAX_LINE_LEN]) {
    FILE *f = fopen(caminho, "r");
    if (!f) {
        fprintf(stderr, "Erro ao abrir '%s': %s\n", caminho, strerror(errno));
        return -1;
    }

    int count = 0;
    while (count < MAX_LINES && fgets(lines[count], MAX_LINE_LEN, f)) {
        lines[count][strcspn(lines[count], "\n")] = '\0';
        count++;
    }
    fclose(f);
    return count;
}

int compareLines(char antes[][MAX_LINE_LEN], int n_antes,
                 char agora[][MAX_LINE_LEN], int n_agora,
                 char diff[][MAX_LINE_LEN], int *n_diff) {
    DeviceEntry entryAntes[n_antes];
    DeviceEntry entryAgora[n_agora];

    for (int i = 0; i < n_antes; i++) {
        parseDeviceLine(antes[i], &entryAntes[i]);
    }
    for (int i = 0; i < n_agora; i++) {
        parseDeviceLine(agora[i], &entryAgora[i]);
    }

    if (n_antes == n_agora) {
        int iguais = 1;
        for (int i = 0; i < n_antes; i++) {
            if (strcmp(antes[i], agora[i]) != 0) {
                iguais = 0;
                break;
            }
        }
        if (iguais) {
            *n_diff = 0;
            return 0; 
        }

        // não precisa tratar esse caso porque ele não vai acontecer

        /*
        int idx = 0;
        printf("Informação completamente alterada (mesmo número de linhas, mas conteúdo distinto)\n");
        
        for (int i = 0; i < n_antes; i++) {
            int encontrado = 0;
            for (int j = 0; j < n_agora; j++) {
                if (strcmp(entryAntes[i].ip, entryAgora[j].ip) == 0) {
                    encontrado = 1;
                    break;
                }
            }
            if (!encontrado) {
                memset(diff[idx], 0, MAX_LINE_LEN);
                strncpy(diff[idx], antes[i], MAX_LINE_LEN - 1);
                diff[idx][MAX_LINE_LEN - 1] = '\0';
                printf("  Dispositivo removido: %s (%s)\n",
                entryAntes[i].hostname,
                entryAntes[i].ip);
                idx++;
            }
        }
        
        for (int i = 0; i < n_agora; i++) {
            int encontrado = 0;
            for (int j = 0; j < n_antes; j++) {
                if (strcmp(entryAgora[i].ip, entryAntes[j].ip) == 0) {
                    encontrado = 1;
                    break;
                }
            }
            if (!encontrado) {
                memset(diff[idx], 0, MAX_LINE_LEN);
                strncpy(diff[idx], agora[i], MAX_LINE_LEN - 1);
                diff[idx][MAX_LINE_LEN - 1] = '\0';
                printf("  Dispositivo adicionado: %s (%s)\n",
                entryAgora[i].hostname,
                entryAgora[i].ip);
                idx++;
            }
        }
        
        *n_diff = idx;
        */
        return 3; 
    }

    if (n_agora < n_antes) {
        int count = 0;
        printf("Informação foi removida\n");
        for (int i = 0; i < n_antes; i++) {
            int encontrado = 0;
            for (int j = 0; j < n_agora; j++) {
                if (strcmp(entryAntes[i].ip, entryAgora[j].ip) == 0) {
                    encontrado = 1;
                    break;
                }
            }
            if (!encontrado) {
                memset(diff[count], 0, MAX_LINE_LEN);
                strncpy(diff[count], antes[i], MAX_LINE_LEN - 1);
                diff[count][MAX_LINE_LEN - 1] = '\0';
                printf("  Dispositivo removido: %s (%s)\n",
                       entryAntes[i].hostname,
                       entryAntes[i].ip);
                count++;
            }
        }
        *n_diff = count;
        return 1;
    }

    if (n_agora > n_antes) {
        int count = 0;
        printf("Informação foi adicionada\n");
        for (int i = 0; i < n_agora; i++) {
            int encontrado = 0;
            for (int j = 0; j < n_antes; j++) {
                if (strcmp(entryAgora[i].ip, entryAntes[j].ip) == 0) {
                    encontrado = 1;
                    break;
                }
            }
            if (!encontrado) {
                memset(diff[count], 0, MAX_LINE_LEN);
                strncpy(diff[count], agora[i], MAX_LINE_LEN - 1);
                diff[count][MAX_LINE_LEN - 1] = '\0';
                printf("  Dispositivo adicionado: %s (%s)\n",
                       entryAgora[i].hostname,
                       entryAgora[i].ip);
                count++;
            }
        }
        *n_diff = count;
        return 2;
    }

    *n_diff = 0;
    return 0;
}

int fileWatcher(const char *nomeArquivo, const char *diretorio, int (*callback_function)(int, char[][MAX_LINE_LEN]), int* closed) {
    char caminhoCompleto[PATH_MAX + 1];
    snprintf(caminhoCompleto, sizeof(caminhoCompleto), "%s/%s", diretorio, nomeArquivo);

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("inotify_init1");
        return 0;
    }

    int wd = inotify_add_watch(fd, diretorio,
                               IN_CLOSE_WRITE |
                               IN_MOVED_TO     |
                               IN_DELETE       | 
                               IN_CREATE       |
                               IN_MODIFY);      
    if (wd == -1) {
        fprintf(stderr, "Erro ao adicionar watch em '%s': %s\n",
                diretorio, strerror(errno));
        close(fd);
        return 0;
    }

    static char antes[MAX_LINES][MAX_LINE_LEN];
    static char agora[MAX_LINES][MAX_LINE_LEN];
    static char lineDiff[MAX_LINES][MAX_LINE_LEN];
    int n_antes = readFile(caminhoCompleto, antes);
    if (n_antes < 0) {
        inotify_rm_watch(fd, wd);
        close(fd);
        return 0;
    }

    printf("Monitorando pasta '%s' [arquivo: %s] para alterações em tempo real...\n",
           diretorio, nomeArquivo);

    char buffer[BUF_LEN];
    while (!*closed) {

        usleep(200 * 1000);

        int length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            perror("read");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            if (event->len > 0) {
                if (strcmp(event->name, nomeArquivo) == 0) {
                    if ((event->mask & IN_CLOSE_WRITE) ||
                        (event->mask & IN_MOVED_TO) ||
                        (event->mask & IN_CREATE) ) {
                        printf("\n==> Detectado SAVE/RENAME em '%s'\n", nomeArquivo);
                        int n_agora = readFile(caminhoCompleto, agora);
                        if (n_agora < 0) {
                            printf("  (Não foi possível ler arquivo '%s' agora.)\n", nomeArquivo);
                        } else {
                            int n_diff = 0;
                            compareLines(antes, n_antes, agora, n_agora, lineDiff, &n_diff);

                            n_antes = n_agora;
                            for (int k = 0; k < n_agora; k++) {
                                strncpy(antes[k], agora[k], MAX_LINE_LEN);
                            }
                        }
                    }
                    if (event->mask & IN_DELETE) {
                        printf("\n==> '%s' foi apagado do disco!\n", nomeArquivo);
                        n_antes = 0;
                    }
                }
            }

            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}
