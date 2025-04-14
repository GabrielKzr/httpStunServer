#include "../include/Utils.h"

cJSON* stun_header_to_json(const StunHeader* header) {
    if (!header) return NULL;

    cJSON* json = cJSON_CreateObject();

    cJSON_AddNumberToObject(json, "type", header->type);
    cJSON_AddNumberToObject(json, "length", header->length);
    cJSON_AddNumberToObject(json, "magic_cookie", header->magic_cookie);

    // Adiciona uuid como array de bytes
    cJSON* uuid_array = cJSON_CreateString((const char*)header->uuid);
    cJSON_AddItemToObject(json, "uuid", uuid_array);

    // Adiciona transaction_id como array de bytes
    cJSON* tid_array = cJSON_CreateString((const char*)header->transaction_id);
    cJSON_AddItemToObject(json, "transaction_id", tid_array);

    return json;
}

// Gera bytes aleatórios
void fill_random_bytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;
    }
}

// Cria um STUN request a partir de um UUID
StunHeader create_stun_request(const uint8_t* uuid) {
    StunHeader header;

    // Define campos básicos
    header.type = 0x0001; // Binding Request (exemplo)
    header.length = 0; // Suponha sem atributos
    header.magic_cookie = MAGIC_COOKIE;

    // Copia o UUID fornecido
    memcpy(header.uuid, uuid, 16);

    // Gera transaction ID aleatório
    fill_random_bytes(header.transaction_id, 12);

    return header;
}