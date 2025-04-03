#include "../include/WebSocketManager.hpp"

void WebSocketManager::add(const std::string& uuid, crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_[uuid] = {conn, {}}; // Inicializa connInfo com a conexão e um vetor vazio
    std::cout << "UUID registrado: " << uuid << std::endl;
}

void WebSocketManager::remove(const std::string& uuid_str) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_.erase(uuid_str);
    std::cout << "Conexão removida para UUID: " << uuid_str << std::endl;
}

void WebSocketManager::sendToUUID(const std::string& uuid, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.count(uuid)) {
        connections_[uuid].conn->send_text(message);
    } else {
        std::cout << "UUID não encontrado: " << uuid << std::endl;
    }
}

void WebSocketManager::broadcast(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [uuid, info] : connections_) {
        info.conn->send_text(message);
    }
}

crow::websocket::connection* WebSocketManager::get_connection(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(uuid);
    return (it != connections_.end()) ? it->second.conn : nullptr;
}

std::string WebSocketManager::get_uuid_by_connection(crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [uuid, info] : connections_) {
        if (info.conn == conn) {
            return uuid;
        }
    }
    return ""; // Retorna vazio se não encontrar
}

int WebSocketManager::getConnPort(crow::websocket::connection* conn, const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [uuid, info] : connections_) {
        if (info.conn == conn) {

            // se a conexão já tem porta definida

            for(int i = 0; i < info.portIpMap.size(); i++) {
                if(info.portIpMap[i] == ip) {
                    return i + BASE_CONN_PORT;
                }
            }

            if(info.portIpMap.size() > MAX_IP_PER_CONNECTION) {
                return -1;
            }

            // se ainda não tem porta definida, porque a conexão é nonva então cria uma porta nova pra aquele ip

            auto _ip = std::string(ip);

            info.portIpMap.push_back(_ip);
            
            return info.portIpMap.size() + BASE_CONN_PORT;
        }
    }
    return -1; // Retorna -1 caso a conexão não seja encontrada
}
