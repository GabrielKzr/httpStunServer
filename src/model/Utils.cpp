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

void generateUUIDBytes(uint8_t uuidArray[16]) {
    boost::uuids::random_generator generator;
    boost::uuids::uuid uuid = generator(); // Usa o gerador estático
    std::memcpy(uuidArray, uuid.data, 16);
}