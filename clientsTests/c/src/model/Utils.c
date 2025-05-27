#include "../include/Utils.h"

void stun_header_to_json(cJSON* json, const StunHeader* header) {
    if (!header) return;

    cJSON_AddNumberToObject(json, "type", header->type);
    cJSON_AddNumberToObject(json, "length", header->length);
    cJSON_AddNumberToObject(json, "magic_cookie", header->magic_cookie);

    // Adiciona uuid como array de bytes
    char uuid_hex[32] = {0};
    bytes_to_hex((uint8_t*)header->uuid, 16, uuid_hex);
    cJSON* uuid_array = cJSON_CreateString(uuid_hex);
    cJSON_AddItemToObject(json, "uuid", uuid_array);

    // Adiciona transaction_id como array de bytes
    char tid_hex[24]; // 24 caracteres + terminador nulo
    bytes_to_hex(header->transaction_id, 12, tid_hex);
    // Adiciona transaction_id como string hexadecimal
    cJSON* tid_item = cJSON_CreateString(tid_hex);
    cJSON_AddItemToObject(json, "transaction_id", tid_item);
}

// Gera bytes aleatórios
void fill_random_bytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;
    }
}

// Cria um STUN request a partir de um UUID
void create_stun_request(StunHeader *header, const uint8_t* uuid, int type) {
    // Define campos básicos
    header->type = type; // Binding Request (exemplo)
    header->length = 0; // Suponha sem atributos
    header->magic_cookie = MAGIC_COOKIE;

    // printf("UUID string: %s (length: %zu)\n", uuid, strlen((char *)uuid));

    char uuid_bytes[16];
    hex_to_bytes((char *)uuid, (unsigned char *)uuid_bytes, 16);

    // Copia o UUID fornecido
    memcpy(header->uuid, uuid_bytes, 16);

    /*
    printf("UUID_BYTES: [");
    for (int i = 0; i < 16; i++) {
        printf("%d", uuid_bytes[i]);
        if (i < 15) {
            printf(", ");
        }
    }
    printf("]\n");
    */

    // Gera transaction ID aleatório
    fill_random_bytes(header->transaction_id, 12);
}

int hex_to_bytes(const char* hex, unsigned char* output, size_t output_len) {
    if (strlen(hex) < output_len * 2) {
        return 0; // String muito curta
    }
    for (size_t i = 0; i < output_len; ++i) {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        char* endptr;
        long byte = strtol(byte_str, &endptr, 16);
        if (endptr != byte_str + 2 || byte < 0 || byte > 255) {
            return 0; // Formato inválido
        }
        output[i] = (unsigned char)byte;
    }
    return 1; // Sucesso
}

// Função auxiliar para converter bytes para string hexadecimal
void bytes_to_hex(const uint8_t* input, size_t len, char* output) {
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        output[i * 2] = hex_chars[(input[i] >> 4) & 0x0F]; // Nibble superior
        output[i * 2 + 1] = hex_chars[input[i] & 0x0F];   // Nibble inferior
    }
    output[len * 2] = '\0'; // Terminador nulo
}

int save_uuid_file(uint8_t *uuid_hex_str) {

    const char *filename = "uuid.txt";

    if (access(filename, F_OK) == 0) {
        printf("Arquivo %s já existe. Não será sobrescrito.\n", filename);
        return 0;
    }

    // printf("Arquivo não tava aberto ainda\n");

    FILE *fp = fopen(filename, "wb");  // ainda em modo binário, mas salva string
    if (!fp) {
        perror("Erro ao abrir uuid.txt para escrita");
        return 0;
    }

    size_t len = strlen((char *)uuid_hex_str);
    if (len != 32) {
        fprintf(stderr, "UUID inválido, tamanho esperado: 32, obtido: %zu\n", len);
        fclose(fp);
        return 0;
    }

    // Debug: imprime os 32 caracteres
    printf("UUID em hexa (string): %s\n", uuid_hex_str);

    // Salva a string como está (32 bytes ASCII)
    size_t written = fwrite(uuid_hex_str, 1, 32, fp);
    fclose(fp);

    // printf("VALORES SALVOSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS\n");

    if (written != 32) {
        fprintf(stderr, "Erro: apenas %zu bytes foram escritos\n", written);
        return 0;
    }

    return 1;
}

int remove_uuid_file() {
    const char *filename = "uuid.txt";

    if (remove(filename) == 0) {
        printf("Arquivo %s removido com sucesso.\n", filename);
        return 1;
    } else {
        perror("Erro ao remover o arquivo");
        return 0;
    }
}

int getUuidFromFile(char* buffer, size_t size, char* path) {

    if (size < 32) {
        printf("Erro: buffer pequeno demais, precisa de pelo menos 32 bytes.\n");
        return 0;
    }

    FILE *file = fopen(path, "rb"); // Abre em modo binário para leitura
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

    size_t lidos = fread(buffer, 1, size, file);
    fclose(file);

    if (lidos != 32) {
        printf("Erro ao ler o arquivo.\n");
        exit(0);
    }  

    return (int)lidos;
}

int unxor_ip(char* ipXor, char* ipOut) {
    uint8_t ip_parts[4];
    if (sscanf(ipXor, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) != 4) return -1;

    uint32_t xor_ip = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
    uint32_t original_ip = xor_ip ^ MAGIC_COOKIE;

    snprintf(ipOut, 16, "%u.%u.%u.%u", (original_ip >> 24) & 0xFF, (original_ip >> 16) & 0xFF, (original_ip >> 8) & 0xFF, original_ip & 0xFF);

    return 1;
}

inline int unxor_port(int xorPort) {
    return xorPort ^ (MAGIC_COOKIE >> 16);
}