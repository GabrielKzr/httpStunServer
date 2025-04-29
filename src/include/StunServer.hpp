#ifndef STUNSERVER_HPP
#define STUNSERVER_HPP

#pragma once

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fstream>

#include "WebSocketManager.hpp"
#include "FirebaseManager.hpp"
#include "Utils.hpp"

typedef struct {
    int socketFd;
    // XorMappedAddress xorMappedAddress;
    // StunHeader stunHeader;
} ClientData;

/*
    * OBS: the message types choosed in this protocol doesn't follow the 
           STUN protocol pattern, the types (values) were just chosen for convenience

        request types:

            * 0x0001: binding request
            * 0x0002: exchange ip request
            * 0x0003: allow router connection (request unique ID using UUiD)
        
        response types:

            * 0x0101: binding response ok (01)
            * 0x0111: binding error response 1 (header received invalid) (01 & 02)
            * 0x0112: binding error response 2 (too much connections in the server) (01 & 02)
            * 0x0113: binding error response 3 (header receiver invalid - magic cookie different) (01 & 02)
            * 0x0200: exchange ip successful (01 & 02)
            * 0x0201: send uuid request (01)
            * 0x0404: bindind error: client not found (02)
            * 0x0500: internal server error (some server bug) (01 & 02)
            * 0x0501: id already binded (01)
    
    Exchange IPs:

        to exchange IPs, the two clients must send the same value for mac_id (should be unique) in the stun header

        buffer send: The buffer that is gonna be sended contains the stunResponse + the XorMappedAddress in this sequence

    Response:

        if error, response goes back w/ just stun header 
        else response goes back w stun header + xor mapped address of the requested client
*/

class StunServer {

    private: 

// --------------------------- atributos -----------------------------

        crow::SimpleApp app;

        WebSocketManager webSocketManager;

        // dados base do servidor
        int port;
        size_t maxClients;

        // controle do banco de dados
        FirebaseManager* firebaseManager;

// -------------------------------------------------------------------

        // funções internas do servidor
        crow::response handleRequest(const crow::request& req);
        crow::response handlePost(const crow::request& req);

        // funções de webSocket
        void handleWebSocketMessage(crow::websocket::connection& conn, const std::string& data, bool is_binary);

        bool addRouterToUser(const std::string& localId, const std::string& uuid, bool status);
        bool handleWebSocketDisconnect(std::string uuid, std::string reason);

        crow::response detectRequestType(StunHeader& stunRequest, std::string* authId, crow::websocket::connection* conn, const std::string* clientIp);
        crow::response clientBind(StunHeader& stunRequest, crow::websocket::connection* conn, std::string* authId);
        crow::response clientBind(StunHeader& stunRequest, crow::websocket::connection* conn);
        crow::response exchangeIpRequest(StunHeader& stunRequest, const std::string& clientIp);
        crow::response exchangeIpPort(connInfo *conn, int port, const std::string& clientIp, const StunHeader& stunRequest);
        crow::response uuidResponse(StunHeader& stunRequest, std::string* authId);
        crow::response sendToRouter(StunHeader& stunRequest, crow::websocket::connection* conn, std::string* authId);
        crow::response removeClient(StunHeader& stunRequest, std::string* authId);

    public:

        bool isClosed = false;

        StunServer(int port, size_t maxClients);
        void stunServerInit();
        void stunServerClose();
        ~StunServer();
};

#endif