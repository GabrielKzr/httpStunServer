#include "include/StunServer.hpp"

StunServer::StunServer(int port, size_t maxClients) {

    this->port = port;
    this->maxClients = maxClients;

    std::ifstream configFile("src/files/google-services.json");

    // Verifica se o arquivo foi aberto corretamente
    if (!configFile.is_open()) {
        std::cerr << "Não foi possível abrir o arquivo google-services.json!" << std::endl;
        return;
    }

// --------------------------------------------------------------------------

    // Lê todo o conteúdo do arquivo para uma string
    std::stringstream buffer;
    buffer << configFile.rdbuf();
    std::string jsonString = buffer.str();

    // Faz o parsing do JSON usando Crow
    auto config = crow::json::load(jsonString);

    if (!config) {
        std::cerr << "Erro ao carregar JSON!" << std::endl;
        return;
    }

    // Acessando os valores no JSON
    std::string FIREBASE_API_KEY = config["client"][0]["api_key"][0]["current_key"].s();
    std::string PROJECT_ID = config["project_info"]["project_id"].s();

// ----------------------------------------------------------------------------

    firebaseManager = new FirebaseManager(PROJECT_ID, FIREBASE_API_KEY);
}

void StunServer::stunServerInit() {

    crow::SimpleApp app;

// ---------------------- gerencia de requsições ----------------------

    CROW_ROUTE(app, "/")
        .methods(crow::HTTPMethod::GET, crow::HTTPMethod::POST)
        ([this](const crow::request& req) {

        return handleRequest(req);
    });

// ---------------------------------------------------------------------

// ---------------------- gerencia de WebSockets -----------------------
    
    CROW_WEBSOCKET_ROUTE(app, "/ws")
        .onopen([](crow::websocket::connection& conn) {
            std::cout << "Cliente conectado! Aguardando UUID..." << std::endl;
        })
        .onmessage([this](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
            this->handleWebSocketMessage(conn, data, is_binary);
        })
        .onclose([this](crow::websocket::connection& conn, const std::string& reason, unsigned short) {
            std::string uuid = webSocketManager.get_uuid_by_connection(&conn);
            if (!uuid.empty()) {
                webSocketManager.remove(uuid);
                std::cout << "Conexão do UUID " << uuid << " fechada: " << reason << std::endl;
            }
        })
        .onerror([](crow::websocket::connection& conn, const std::string& error) {
            std::cerr << "Erro: " << error << std::endl;
        });

    app.port(this->port).multithreaded().run();
}

crow::response StunServer::handleRequest(const crow::request& req) {
    
    if (req.method == crow::HTTPMethod::GET) {

        return crow::response(200, "Recebi um GET");

    } else if (req.method == crow::HTTPMethod::POST) {
        
        return handlePost(req);

    }
    return crow::response(400, "Método não suportado");
}

crow::response StunServer::handlePost(const crow::request& req) {

    StunHeader stunRequest;
    crow::response response;
    const std::string* clientIp = &(req.remote_ip_address);
    
// -------------------------- análise do stun request --------------------------

    auto json_body = crow::json::load(req.body);

    if (!json_body) {
        return crow::response(400, "header received invalid");
    }
    
    try {
        stunRequest = jsonToStunHeader(json_body);
    } catch(const std::exception& e) {
        return crow::response(400, "header received invalid");
    }

    // Análise de máximo de conexões, porém vai ser com websockets, e está relacionada com o roteador, talvez seja outra ponta do server

    if(stunRequest.magic_cookie != MAGIC_COOKIE) {
        return crow::response(400, "header receiver invalid - magic cookie different");
    }

// -------------------------------------------------------------------------------------

// ------------------------- verificação do tipo de request ----------------------------

    if (json_body.has("auth_id")) {

        std::string auth_id;
        auth_id = json_body["auth_id"].s();

        response = detectRequestType(stunRequest, &auth_id, nullptr, clientIp);
    } else {
        response = detectRequestType(stunRequest, nullptr, nullptr, nullptr);
    }

// --------------------------------------------------------------------------------------

    return response;
}

crow::response StunServer::detectRequestType(StunHeader& stunRequest, std::string* authId, crow::websocket::connection* conn, const std::string* clientIp) {



    switch (stunRequest.type)
    {
    case 0x0001: // binding request

        return this->clientBind(stunRequest, conn);
    
    case 0x0002: // ip request 

        std::cout << "Ip exchange request\n";

        /* // precisa ativar quando vincular com o dart
        if(!firebaseManager->verifyGoogleIdToken(*authId)) {
            break;
        }    
        */

        return this->exchangeIpRequest(stunRequest, *clientIp);

    // provavelmente depois vão ter mais tipos de request

    case 0x0003: // uuid request

        std::cout << "Receive uuid request\n";

        std::cout << authId << std::endl;

        /* // precisa ativar quando vincular com o dart
        if(!firebaseManager->verifyGoogleIdToken(*authId)) {
            break;
        }    
        */

        generateUUIDBytes(stunRequest.uuid);

        return crow::response(200, stunHeaderToJson(stunRequest));

    default:

        return crow::response(404, "stun request type does not exist");
    }

    return crow::response(200, "testando post");
}

crow::response StunServer::clientBind(StunHeader& stunRequest, crow::websocket::connection* conn) {

    std::string uuid(reinterpret_cast<const char*>(stunRequest.uuid), 16);

    json j;
    int statusCode = 0;

    if(webSocketManager.get_connection(uuid) == nullptr) {
        webSocketManager.add(uuid, conn);
        std::cout << "UUID registrado: " << uuid << std::endl;

        j = {{"status", "success"}, {"message", "UUID registrado: " + uuid}};
        statusCode = 200;

        conn->send_text(j.dump());
    } else {
        std::cout << "UUID já registrado: " << uuid << std::endl;

        j = {{"status", "error"}, {"message", "UUID já está em uso"}};
        statusCode = 400;

        conn->send_text(j.dump());
    }

    return crow::response(statusCode, j.dump());
}

crow::response StunServer::exchangeIpRequest(StunHeader& stunRequest, const std::string& clientIp) {

    std::string uuid(reinterpret_cast<const char*>(stunRequest.uuid), 16);

    if(webSocketManager.get_connection(uuid) == nullptr) {
        return crow::response(400, "client UUID not found");
    }

    // ------------- tratar o resto do ip request


    // ---------------------------------------------------------------

}

void StunServer::handleWebSocketMessage(crow::websocket::connection& conn, const std::string& data, bool is_binary) {

    static std::unordered_map<crow::websocket::connection*, std::string> pendingConnections;

    if(!is_binary) {

        try {

            json j = json::parse(data);

            StunHeader stunRequest = jsonNlohmannToStunHeader(j);

            this->detectRequestType(stunRequest, nullptr, &conn, nullptr);

        } catch (const json::exception& e) {
            std::cout << "Erro ao parsear JSON: " << e.what() << std::endl;
            conn.send_text(json{{"status", "error"}, {"message", "JSON inválido"}}.dump());
        }
    } else {
        std::cout << "Mensagem binária ignorada" << std::endl;
        conn.send_text(json{{"status", "error"}, {"message", "Apenas JSON (texto) é aceito"}}.dump());
    }
}

void StunServer::stunServerClose() {
    app.stop();
}

StunServer::~StunServer() {
    delete firebaseManager;
}

