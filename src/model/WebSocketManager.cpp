#include "../include/WebSocketManager.hpp"

void WebSocketManager::add(const std::string& uuid, crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_[uuid] = conn;
    std::cout << "UUID registrado: " << uuid << std::endl;
}

void WebSocketManager::remove(const std::string& uuid_str) {
    connections_.erase(uuid_str);
    std::cout << "Conexão removida para UUID: " << uuid_str << std::endl;
}

void WebSocketManager::sendToUUID(const std::string& uuid, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.count(uuid)) {
        connections_[uuid]->send_text(message);
    } else {
        std::cout << "UUID não encontrado: " << uuid << std::endl;
    }
}

void WebSocketManager::broadcast(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [uuid, conn] : connections_) {
        conn->send_text(message);
    }
}

crow::websocket::connection* WebSocketManager::get_connection(const std::string& uuid) {
    auto it = connections_.find(uuid);
    return (it != connections_.end()) ? it->second : nullptr;
}

std::string WebSocketManager::get_uuid_by_connection(crow::websocket::connection* conn) {
    for (const auto& [key, connection] : connections_) {
        if (connection == conn) {
            return key;
        }
    }
    return ""; // Retorna vazio se não encontrar
}

void WebSocketManager::handleMessage(crow::websocket::connection& conn, const std::string& data) {

}
