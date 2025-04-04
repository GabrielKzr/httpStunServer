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

    // Magic cookie é obrigatório
    if(!json.has("magic_cookie")) {
        throw std::runtime_error("Campo 'magic_cookie' é obrigatório");
    }
    
    header.magic_cookie = static_cast<uint32_t>(json["magic_cookie"].i());

    // UUID - obrigatório
    if (!json.has("uuid")) {
        throw std::runtime_error("Campo 'uuid' é obrigatório");
    }
    std::string uuid_str = json["uuid"].s();
    if (uuid_str.length() < 16) {
        throw std::runtime_error("UUID deve ter pelo menos 16 bytes");
    }
    std::memcpy(header.uuid, uuid_str.data(), 16);

    // Transaction ID - obrigatório
    if (!json.has("transaction_id")) {
        throw std::runtime_error("Campo 'transaction_id' é obrigatório");
    }
    std::string tid_str = json["transaction_id"].s();
    if (tid_str.length() < 12) {
        throw std::runtime_error("Transaction ID deve ter pelo menos 12 bytes");
    }
    std::memcpy(header.transaction_id, tid_str.data(), 12);

    return header;
}

StunHeader jsonNlohmannToStunHeader(const json& json) {
    StunHeader header{};
    
    // Type - obrigatório
    if (!json.contains("type")) {
        throw std::runtime_error("Campo 'type' é obrigatório");
    }   
    header.type = json["type"].get<uint16_t>();

    // Length - obrigatório
    if (!json.contains("length")) {
        throw std::runtime_error("Campo 'length' é obrigatório");
    }

    header.length = json["length"].get<uint16_t>();

    // Magic cookie é obrigatório
    if(!json.contains("magic_cookie")) {
        throw std::runtime_error("Campo 'magic_cookie' é obrigatório");
    }
    
    header.magic_cookie = json["magic_cookie"].get<uint32_t>();

    // UUID - obrigatório
    if (!json.contains("uuid") && json["uuid"].is_string()) {
        throw std::runtime_error("Campo 'uuid' é obrigatório");
    }
    std::string uuid_str = json["uuid"].get<std::string>();
    if (uuid_str.length() < 16) {
        throw std::runtime_error("UUID deve ter pelo menos 16 bytes");
    }
    std::memcpy(header.uuid, uuid_str.data(), 16);

    // Transaction ID - obrigatório
    if (!json.contains("transaction_id") && json["transaction_id"].is_string()) {
        throw std::runtime_error("Campo 'transaction_id' é obrigatório");
    }
    std::string tid_str = json["transaction_id"].get<std::string>();
    if (tid_str.length() < 12) {
        throw std::runtime_error("Transaction ID deve ter pelo menos 12 bytes");
    }
    std::memcpy(header.transaction_id, tid_str.data(), 12);

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

    // UUID como string original
    std::string uuid_str(reinterpret_cast<const char*>(header.uuid), 16);
    json["uuid"] = uuid_str;

    // Transaction ID como string original
    std::string tid_str(reinterpret_cast<const char*>(header.transaction_id), 12);
    json["transaction_id"] = tid_str;

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

    std::string uuid_str(reinterpret_cast<const char*>(header.uuid), 16);
    j["uuid"] = uuid_str;

    std::string tid_str(reinterpret_cast<const char*>(header.transaction_id), 12);
    j["transaction_id"] = tid_str;

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