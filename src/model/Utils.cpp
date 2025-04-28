#include "../include/Utils.hpp"

// Função para converter JSON para StunHeader
StunHeader jsonToStunHeader(const crow::json::rvalue& json) {
    StunHeader header{};
    
    // Verifica se é um objeto JSON válido
    if (json.t() != crow::json::type::Object) {
        throw std::runtime_error("JSON deve ser um objeto");
    }

    // Type - obrigatório
    if (!json.has("type")) {
        throw std::runtime_error("Campo 'type' é obrigatório");
    }   
    header.type = static_cast<uint16_t>(json["type"].i());

    // Length - obrigatório
    if (!json.has("length")) {
        throw std::runtime_error("Campo 'length' é obrigatório");
    }
    header.length = static_cast<uint16_t>(json["length"].i());

    // Magic cookie - obrigatório
    if (!json.has("magic_cookie")) {
        throw std::runtime_error("Campo 'magic_cookie' é obrigatório");
    }
    header.magic_cookie = static_cast<uint32_t>(json["magic_cookie"].i());

    std::cout << "ADASFMDFKAMSFAKSMASKD\n";

    // UUID - obrigatório, agora como string hexadecimal
    if (!json.has("uuid")) {
        throw std::runtime_error("Campo 'uuid' é obrigatório");
    }
    std::string uuid_str = json["uuid"].s();

    std::cout << uuid_str << std::endl;

    if (uuid_str.length() != 32) { // 16 bytes * 2 (cada byte vira 2 chars hex)
        throw std::runtime_error("UUID deve ter 32 caracteres hexadecimais");
    } else {
        std::cout << uuid_str.size() << std::endl;
    }

    std::cout << "ADASFMDFKAMSFAKSMASKD\n";
    hex_to_bytes(uuid_str, header.uuid, 16);

    // Transaction ID - obrigatório, agora como string hexadecimal
    if (!json.has("transaction_id")) {
        throw std::runtime_error("Campo 'transaction_id' é obrigatório");
    }
    std::string tid_str = json["transaction_id"].s();
    if (tid_str.length() != 24) { // 12 bytes * 2 (cada byte vira 2 chars hex)
        throw std::runtime_error("Transaction ID deve ter 24 caracteres hexadecimais");
    }
    hex_to_bytes(tid_str, header.transaction_id, 12);

    return header;
}

StunHeader jsonNlohmannToStunHeader(const json& json) {
    StunHeader header{};
    
    // Type - obrigatório
    if (!json.contains("type") || !json["type"].is_number_integer()) {
        throw std::runtime_error("Campo 'type' é obrigatório e deve ser um inteiro");
    }   
    header.type = json["type"].get<uint16_t>();

    // Length - obrigatório
    if (!json.contains("length") || !json["length"].is_number_integer()) {
        throw std::runtime_error("Campo 'length' é obrigatório e deve ser um inteiro");
    }
    header.length = json["length"].get<uint16_t>();

    // Magic cookie - obrigatório
    if (!json.contains("magic_cookie") || !json["magic_cookie"].is_number_integer()) {
        throw std::runtime_error("Campo 'magic_cookie' é obrigatório e deve ser um inteiro");
    }
    header.magic_cookie = json["magic_cookie"].get<uint32_t>();

    // UUID - obrigatório, agora como string hexadecimal
    if (!json.contains("uuid") || !json["uuid"].is_string()) {
        throw std::runtime_error("Campo 'uuid' é obrigatório e deve ser uma string");
    }
    std::string uuid_str = json["uuid"].get<std::string>();
    if (uuid_str.length() != 32) { // 16 bytes * 2 (cada byte vira 2 chars hex)
        throw std::runtime_error("UUID deve ter 32 caracteres hexadecimais");
    }
    hex_to_bytes(uuid_str, header.uuid, 16);

    // Transaction ID - obrigatório, agora como string hexadecimal
    if (!json.contains("transaction_id") || !json["transaction_id"].is_string()) {
        throw std::runtime_error("Campo 'transaction_id' é obrigatório e deve ser uma string");
    }
    std::string tid_str = json["transaction_id"].get<std::string>();
    if (tid_str.length() != 24) { // 12 bytes * 2 (cada byte vira 2 chars hex)
        throw std::runtime_error("Transaction ID deve ter 24 caracteres hexadecimais");
    }
    hex_to_bytes(tid_str, header.transaction_id, 12);

    return header;
}

// Função para converter StunHeader para crow::json::wvalue
crow::json::wvalue stunHeaderToJson(const StunHeader& header) {
    if (header.magic_cookie != 0x2112A442) {
        throw std::runtime_error("Magic cookie inválido. Esperado: 0x2112A442");
    }

    crow::json::wvalue json;

    // Type
    json["type"] = header.type;

    // Length
    json["length"] = header.length;

    // Magic Cookie
    json["magic_cookie"] = header.magic_cookie;

    // UUID como string hexadecimal
    json["uuid"] = bytes_to_hex(header.uuid, 16);

    // Transaction ID como string hexadecimal
    json["transaction_id"] = bytes_to_hex(header.transaction_id, 12);

    return json;
}

json stunHeaderToJsonNlohmann(const StunHeader& header) {
    if (header.magic_cookie != 0x2112A442) {
        throw std::runtime_error("Magic cookie inválido. Esperado: 0x2112A442");
    }

    json j;

    j["type"] = header.type;

    j["length"] = header.length;

    j["magic_cookie"] = header.magic_cookie;

    j["uuid"] = bytes_to_hex(header.uuid, 16);

    j["transaction_id"] = bytes_to_hex(header.transaction_id, 12);

    return j;
}

XorMappedAddress buildXorMappedAddress(int port, std::string clientIp) {

    XorMappedAddress xorAddr;

    xorAddr.type = htons(0x0020);
    xorAddr.length = htons(8);
    xorAddr.reserved = 0x00;
    xorAddr.family = 0x01;
    xorAddr.xor_port = htons(port ^ (MAGIC_COOKIE >> 16));

    struct in_addr addr;
    if (inet_pton(AF_INET, clientIp.c_str(), &addr) != 1) {
        // Se a conversão falhar, defina um IP padrão ou trate o erro.
        std::cerr << "Erro: IP inválido" << std::endl;
        throw std::runtime_error("IP inválido");
    }

    xorAddr.xor_ip = htonl(ntohl(addr.s_addr) ^ MAGIC_COOKIE);

    return xorAddr;
}

json xorMappedAddressToJsonNlohmann(const XorMappedAddress& xorAddr) {
    // Verifica se o tipo é válido
    if (ntohs(xorAddr.type) != 0x0020) {
        throw std::runtime_error("Tipo inválido. Esperado: 0x0020 (XOR-MAPPED-ADDRESS)");
    }

    json j;

    // Adiciona os campos básicos
    j["xor_type"] = ntohs(xorAddr.type);          // Converte de network byte order para host
    j["xor_length"] = ntohs(xorAddr.length);      // Converte de network byte order para host
    j["reserved"] = xorAddr.reserved;
    j["family"] = xorAddr.family;

    // Decodifica a porta XOR usando o MAGIC_COOKIE (assumindo 0x2112A442 como no exemplo)
    uint16_t port = ntohs(xorAddr.xor_port) ^ (MAGIC_COOKIE >> 16);
    j["xor_port"] = port;

    // Decodifica o IP XOR (apenas IPv4 por enquanto, family = 0x01)
    if (xorAddr.family == 0x01) {
        uint32_t ip = ntohl(xorAddr.xor_ip) ^ MAGIC_COOKIE;
        struct in_addr addr;
        addr.s_addr = htonl(ip); // Converte de volta para network byte order para inet_ntop
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        j["xor_ip"] = std::string(ip_str);
    } else if (xorAddr.family == 0x02) {
        // Para IPv6, seria necessário um tratamento diferente (não implementado aqui)
        throw std::runtime_error("IPv6 não suportado nesta implementação");
    } else {
        throw std::runtime_error("Família de endereço desconhecida");
    }

    return j;
}

void generateUUIDBytes(uint8_t uuidArray[16]) {
    boost::uuids::random_generator generator;
    boost::uuids::uuid uuid = generator(); // Usa o gerador estático
    std::memcpy(uuidArray, uuid.data, 16);
}

std::string base64_encode(const unsigned char* bytes, size_t length) {
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    for (size_t n = 0; n < length; n++) {
        char_array_3[i++] = bytes[n];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

std::string base64_decode(const std::string& encoded_string) {
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded_data;
    int in_len = encoded_string.size();
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && encoded_string[i] != '=' && base64_chars.find(encoded_string[i]) != std::string::npos) {
        char_array_4[j++] = encoded_string[i++];
        if (j == 4) {
            for (int k = 0; k < 4; k++) {
                char_array_4[k] = base64_chars.find(char_array_4[k]);
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];

            decoded_data.append(reinterpret_cast<char*>(char_array_3), 3);
            j = 0;
        }
    }

    if (j) {
        for (int k = j; k < 4; k++) {
            char_array_4[k] = 0;
        }
        for (int k = 0; k < 4; k++) {
            char_array_4[k] = base64_chars.find(char_array_4[k]);
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        decoded_data.append(reinterpret_cast<char*>(char_array_3), j - 1);
    }

    return decoded_data;
}

void hex_to_bytes(const std::string& hex, uint8_t* output, size_t output_len) {
    if (hex.length() < output_len * 2) {
        throw std::runtime_error("String hexadecimal muito curta");
    }
    for (size_t i = 0; i < output_len; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        try {
            output[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        } catch (...) {
            throw std::runtime_error("Formato hexadecimal inválido");
        }
    }
}

std::string bytes_to_hex(const uint8_t* input, size_t len) {
    std::string result;
    result.reserve(len * 2);
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        result += hex_chars[(input[i] >> 4) & 0x0F]; // Nibble superior
        result += hex_chars[input[i] & 0x0F];       // Nibble inferior
    }
    return result;
}

bool jsonContainsUUID(const nlohmann::json& j, const std::string& uuid) {
    if (j.is_object()) {
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.key() == uuid) {
                return true;
            }
            if (jsonContainsUUID(it.value(), uuid)) {
                return true;
            }
        }
    } else if (j.is_array()) {
        for (const auto& item : j) {
            if (jsonContainsUUID(item, uuid)) {
                return true;
            }
        }
    }
    return false;
}
