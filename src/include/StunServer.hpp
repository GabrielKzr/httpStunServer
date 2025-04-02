#ifndef STUNSERVER_HPP
#define STUNSERVER_HPP

#pragma once

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <iomanip>
#include <netinet/tcp.h>
#include <fstream>

#include <curl/curl.h>

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
            * 0x0003: different STUN transaction ID
            * 0x0004: allow router connection (request unique ID using UUiD)
        
        response types:

            * 0x0080: waiting user auth token (01)
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


        bool authClient(int sock);
        // bool stunClientInit(StunHeader* stunHeader, int sockFd);
        crow::response detectRequestType(StunHeader& stunRequest, std::string* authId, crow::websocket::connection* conn);
        bool exchangeIpPort(ClientData* requestClient, ClientData* connectedClient);
        crow::response clientBind(StunHeader& stunRequest, crow::websocket::connection* conn);

        // funções de busca
        bool findData(ClientData* data, ClientData* cmpval);
        bool findTransactionId(ClientData* data, ClientData* cmpval);

    public:

        bool isClosed = false;

        StunServer(int port, size_t maxClients);
        void stunServerInit();
        void stunServerClose();
        ~StunServer();
};

#endif