#ifndef WEBSOCKETMANAGER_HPP
#define WEBSOCKETMANAGER_HPP

#include "Utils.hpp"

#include <unordered_set>
#include <mutex>

class WebSocketManager
{
private:

    std::mutex mutex_; // Para evitar race conditions ao acessar a lista

public:

    std::unordered_map<std::string, crow::websocket::connection*> connections_;

    void add(const std::string& uuid, crow::websocket::connection* conn);
    void remove(const std::string& uuid_str);
    void sendToUUID(const std::string& uuid, const std::string& message);
    void broadcast(const std::string& message);

    void handleMessage(crow::websocket::connection& conn, const std::string& data);

    crow::websocket::connection* get_connection(const std::string& uuid);
    std::string get_uuid_by_connection(crow::websocket::connection* conn);
};

#endif