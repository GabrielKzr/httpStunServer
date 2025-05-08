#ifndef WEBSOCKETMANAGER_HPP
#define WEBSOCKETMANAGER_HPP

#include "Utils.hpp"

#include <unordered_set>
#include <mutex>
#include <vector>

struct connInfo {
    crow::websocket::connection* conn;
    std::vector<std::string> portIpMap;
    StunHeader header;
};

class WebSocketManager
{
private:

    std::mutex mutex_; // Para evitar race conditions ao acessar a lista
    std::unordered_map<std::string, connInfo> connections_;

    const int BASE_CONN_PORT = 2222;
    const int MAX_IP_PER_CONNECTION = 100;

public:

    bool add(const std::string& uuid, crow::websocket::connection* conn, const StunHeader& header);
    void remove(const std::string& uuid_str);
    void sendToUUID(const std::string& uuid, const std::string& message);
    void broadcast(const std::string& message);

    int getConnPort(crow::websocket::connection* conn, const std::string& ip);

    connInfo* get_connection(const std::string& uuid);
    std::string get_uuid_by_connection(crow::websocket::connection* conn);
};

#endif