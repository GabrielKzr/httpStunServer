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

    firebaseManager = new FirebaseManager(PROJECT_ID, FIREBASE_API_KEY, "src/files/sigmarr-c99af-firebase-adminsdk-fbsvc-8f8bd7b716.json");
}

void StunServer::stunServerInit() {

    crow::SimpleApp app;

    firebaseDataInit();

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
            handleWebSocketDisconnect(uuid, reason);
        })
        .onerror([](crow::websocket::connection& conn, const std::string& error) {
            std::cerr << "Erro: " << error << std::endl;
        });


    // ——> aqui você cria o contexto SSL manualmente:
    asio::ssl::context ctx{asio::ssl::context::tlsv12};
    // não pede nem verifica certificado do cliente
    ctx.set_verify_mode(asio::ssl::verify_none);
    // usa seu cert.pem e key.pem
    ctx.use_certificate_chain_file("src/files/cert.pem");
    ctx.use_private_key_file("src/files/key.pem", 
                             asio::ssl::context::file_format::pem);

    // roda o app com esse contexto, em vez de usar ssl_file()
    app
      .port(this->port)
      .ssl(std::move(ctx))
      .multithreaded()
      .run();
}

void StunServer::firebaseDataInit() {
    
    std::string response = firebaseManager->sendRequest("users", "", "", GET);
    nlohmann::json jsonData = nlohmann::json::parse(response);

    if (!jsonData.contains("documents")) {
        std::cerr << "Resposta do Firebase não contém documentos: " << response << std::endl;
        return;
    }

    for (const auto& user : jsonData["documents"]) {
        if (!user.is_object() || !user.contains("fields") || !user["fields"].contains("routers")) {
            continue;
        }

        // 3. Faz uma cópia COMPLETA dos routers do usuário
        nlohmann::json userData = user["fields"];
        auto& routers = userData["routers"]["mapValue"]["fields"];
        
        bool updated = false; // Flag para verificar se algum router foi atualizado

        // 4. Itera por cada uuid nos routers
        for (auto& [uuid, router] : routers.items()) {
            // Atualiza o campo activity para false
            router["mapValue"]["fields"]["activity"] = {{"booleanValue", false}};
            updated = true; // Marca que houve atualização
        }

        if (updated) {
            // 5. Extrai o ID do usuário
            std::string fullPath = user["name"];
            std::string userId = fullPath.substr(fullPath.rfind('/') + 1);

            // 6. Monta o payload com TODOS os campos do usuário
            nlohmann::json patchData = {
                {"fields", {
                    {"routers", userData["routers"]},  // Envia todos os routers
                }}
            };

            // 7. Envia a requisição
            firebaseManager->sendRequest("users", userId, patchData.dump(), PATCH);
            std::cout << "Todos os routers do usuário " << userId << " atualizados. Activity: false" << std::endl;
        }
    }

}

bool StunServer::handleWebSocketDisconnect(std::string uuid, std::string reason) {
    if (!uuid.empty()) {
        webSocketManager.remove(uuid);
        std::cout << "Conexão do UUID " << uuid << " fechada: " << reason << std::endl;

        try {
            // 1. Faz GET de todos os usuários
            std::string response = firebaseManager->sendRequest("users", "", "", GET);
            nlohmann::json jsonData = nlohmann::json::parse(response);

            if (!jsonData.contains("documents")) {
                std::cerr << "Resposta do Firebase não contém documentos: " << response << std::endl;
                return false;
            }

            // 2. Itera sobre os documentos
            for (const auto& user : jsonData["documents"]) {
                if (!user.is_object() || !user.contains("fields") || !user["fields"].contains("routers")) {
                    continue;
                }

                // 3. Faz uma cópia COMPLETA dos routers do usuário
                nlohmann::json userData = user["fields"];
                auto& routers = userData["routers"]["mapValue"]["fields"];
                
                if (routers.contains(uuid)) {
                    // 4. Atualiza apenas o router específico mantendo outros campos
                    routers[uuid]["mapValue"]["fields"]["activity"] = {{"booleanValue", false}};

                    // 5. Extrai o ID do usuário
                    std::string fullPath = user["name"];
                    std::string userId = fullPath.substr(fullPath.rfind('/') + 1);

                    // 6. Monta o payload com TODOS os campos do usuário
                    nlohmann::json patchData = {
                        {"fields", {
                            {"routers", userData["routers"]},  // Envia todos os routers
                        }}
                    };

                    // 7. Envia a requisição
                    firebaseManager->sendRequest("users", userId, patchData.dump(), PATCH);
                    std::cout << "Router " << uuid << " atualizado. Activity: false (outros routers preservados)" << std::endl;
                    break;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Erro ao processar fechamento de conexão: " << e.what() << std::endl;
        }
    }

    return false;
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
        std::cout << "Header received Invalid\n";
        return crow::response(400, "header received invalid");
    }

    // Análise de máximo de conexões, porém vai ser com websockets, e está relacionada com o roteador, talvez seja outra ponta do server

    if(stunRequest.magic_cookie != MAGIC_COOKIE) {
        return crow::response(400, "header receiver invalid - magic cookie different");
    }

// -------------------------------------------------------------------------------------

    std::string auth_id;

    if (json_body.has("auth_id")) {

        auth_id = json_body["auth_id"].s();

    } else {

        crow::response(400, "Necessário ID de indentificação");

    }

    std::cout << "Cheguei aqui\n";
    // ------------------------- verificação do tipo de request ----------------------------

    return this->detectRequestType(stunRequest, &auth_id, nullptr, clientIp);;

    // --------------------------------------------------------------------------------------

}

crow::response StunServer::detectRequestType(StunHeader& stunRequest, std::string* authId, crow::websocket::connection* conn, const std::string* clientIp) {

    std::cout << stunRequest.type << std::endl;

    switch (stunRequest.type)
    {
    case 0x0001: // binding request

        return this->sendToRouter(stunRequest, conn, authId);
    
    case 0x0002: // ip request 

        std::cout << "Ip exchange request\n";

        return this->exchangeIpRequest(stunRequest, *clientIp, *authId);

    // provavelmente depois vão ter mais tipos de request

    case 0x0003: // uuid request

        // transformar isso em uma função 

        return this->uuidResponse(stunRequest, authId);

    case 0x0004: // recebido do router 

        return this->clientBind(stunRequest, conn, authId);

    case 0x0005: // recebido do router

        return this->clientBind(stunRequest, conn);

    case 0x0006:

        return this->removeClient(stunRequest, authId);

    case 0x0007:

        return this->getRemoteIp(stunRequest, *clientIp);

    default:

        return crow::response(404, "stun request type does not exist");
    }

    return crow::response(200, "testando post");
}

crow::response StunServer::clientBind(StunHeader& stunRequest, crow::websocket::connection* conn) {

    std::string uuid = bytes_to_hex(stunRequest.uuid, 16);

    std::cout << "CLIENT BIND SEM AUTH\n";

    try {
        // 1. Faz GET de todos os usuários
        std::string response = firebaseManager->sendRequest("users", "", "", GET);
        nlohmann::json jsonData = nlohmann::json::parse(response);

        if (!jsonData.contains("documents")) {
            std::cerr << "Resposta do Firebase não contém documentos: " << response << std::endl;
            conn->send_text(json{{"status", "error"}, {"message", "Firebase não contém documentos"}}.dump());
            return crow::response(400, "error: não foi possível encontrar documento");
        }

        if (!jsonContainsUUID(jsonData, uuid)) {
            std::cout << "UUID não encontrado no JSON!" << std::endl;
            conn->send_text(json{{"status", "absent"}, {"message", "UUID não encontrado no JSON"}}.dump());
            conn->close(); // fecha conexão, pois não está autenticada
            return crow::response(400, "error: não foi possível encontrar uuid");
        }

        // 2. Itera sobre os documentos
        for (const auto& user : jsonData["documents"]) {
            if (!user.is_object() || !user.contains("fields") || !user["fields"].contains("routers")) {
                continue;
            }

            // 3. Faz uma cópia COMPLETA dos routers do usuário
            nlohmann::json userData = user["fields"];
            auto& routers = userData["routers"]["mapValue"]["fields"];
            
            if (routers.contains(uuid)) {
                // 4. Atualiza apenas o router específico mantendo outros campos
                routers[uuid]["mapValue"]["fields"]["activity"] = {{"booleanValue", true}};

                // 5. Extrai o ID do usuário
                std::string fullPath = user["name"];
                std::string userId = fullPath.substr(fullPath.rfind('/') + 1);

                // 6. Monta o payload com TODOS os campos do usuário
                nlohmann::json patchData = {
                    {"fields", {
                        {"routers", userData["routers"]},  // Envia todos os routers
                    }}
                };

                // 7. Envia a requisição
                firebaseManager->sendRequest("users", userId, patchData.dump(), PATCH);
                std::cout << "Router " << uuid << " atualizado. Activity: false (outros routers preservados)" << std::endl;
                break;
            }
        }

        webSocketManager.add(uuid, conn, stunRequest);

        json responseJson = stunHeaderToJsonNlohmann(stunRequest);

        responseJson.update(nlohmann::json{   
            {"status", "connected"}
        });
      
        conn->send_text(responseJson.dump());

        return crow::response(200, "success: status de roteador atualizado com sucesso");

    } catch (const std::exception& e) {

        json responseJson = stunHeaderToJsonNlohmann(stunRequest);
        responseJson.update(nlohmann::json{   
            {"status", "error"}
        });

        std::cerr << "Erro ao processar fechamento de conexão: " << e.what() << std::endl;
        return crow::response(400, "error: Erro ao comunicar com o Firebase");
    }
}

// aqui só entra depois que o roteador já confirmou a validade das informações (tudo validado com authId)
crow::response StunServer::clientBind(StunHeader& stunRequest, crow::websocket::connection* conn, std::string* authId) {

    std::string localId;

    json j;
    int statusCode = 0;

    std::string uuid = bytes_to_hex(stunRequest.uuid, 16);

    // precisa ativar quando vincular com o dart
    if(!firebaseManager->verifyGoogleIdToken(*authId, &localId)) {
        return crow::response(400, "Auth ID invalid");
    }

    if(!addRouterToUser(localId, uuid, true)) {
        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "error"}});

        conn->send_text(j.dump());
        statusCode = 400;
        crow::response(statusCode, j.dump());
    }

    if(webSocketManager.add(uuid, conn, stunRequest)) {

        std::cout << "UUID registrado: " << uuid << std::endl;

        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "connected"}});
        statusCode = 200;

        conn->send_text(j.dump());
    } else {

        std::cout << "UUID já registrado: " << uuid << std::endl;
        
        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "error"}});
        statusCode = 400;

        conn->send_text(j.dump());
    }

    return crow::response(statusCode, j.dump());
}

// função que manda para roteador salvar uuid (não salva nada no servidor ainda)
crow::response StunServer::sendToRouter(StunHeader& stunRequest, crow::websocket::connection* conn, std::string* authId) {

    json j;

    if(authId == nullptr) {
        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "error"}});
        conn->send_text(j.dump());
        return crow::response(400, "Missing auth ID");
    }

    if(!firebaseManager->verifyGoogleIdToken(*authId)) {
        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "error"}});
        conn->send_text(j.dump());
        return crow::response(400, "Auth ID invalid");
    }

    std::cout << "Entro no sendToRouter\n";

    int statusCode = 0;

    std::string uuid = bytes_to_hex(stunRequest.uuid, 16);

    if(webSocketManager.get_connection(uuid) == nullptr) {

        std::cout << "UUID registrado: " << uuid << std::endl;

        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "success"}, {"auth_id", *authId}});
        statusCode = 200;

        conn->send_text(j.dump());

    } else {
        std::cout << "UUID já registrado: " << uuid << std::endl;

        j = stunHeaderToJsonNlohmann(stunRequest);
        j.update({{"status", "error"}});
        statusCode = 400;

        conn->send_text(j.dump());
    }

    return crow::response(statusCode, j.dump());
}

bool StunServer::clientHasUuid(const std::string& uuid, const std::string& idToken) {
    // Envia uma requisição ao Firebase para obter os dados do usuário específico identificado por idToken
    std::string response = firebaseManager->sendRequest("users", idToken, "", GET);

    std::cout << "\n==================================================================\n";

    std::cout << response << std::endl;

    std::cout << "\n==================================================================\n";

    // Tenta parsear a resposta como JSON
    nlohmann::json jsonData;
    try {
        jsonData = nlohmann::json::parse(response);
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "Erro ao parsear resposta do Firebase: " << e.what() << std::endl;
        return false;
    }

    // Verifica se a resposta contém os dados do usuário
    if (!jsonData.is_object() || !jsonData.contains("fields") || !jsonData["fields"].contains("routers")) {
        std::cerr << "Resposta do Firebase não contém os dados esperados para o usuário: " << idToken << std::endl;
        return false;
    }

    // Acessa os routers do usuário
    nlohmann::json userData = jsonData["fields"];
    auto& routers = userData["routers"]["mapValue"]["fields"];

    std::cout << "\n==================================================================\n";

    std::cout << uuid << std::endl;

    std::cout << routers << std::endl;

    std::cout << "\n==================================================================\n";

    // Verifica se o uuid está presente nos routers
    return routers.contains(uuid);
}

crow::response StunServer::exchangeIpRequest(StunHeader& stunRequest, const std::string& clientIp, const std::string& authId) {

    std::string uuid = bytes_to_hex(stunRequest.uuid, 16);

    std::string localId;

    if(!firebaseManager->verifyGoogleIdToken(authId, &localId)) {
        return crow::response(400, "Auth ID invalid");
    }    

    // verifica se o cliente tem o uuid do roteador requisitado vinculado ao seu próprio id
    if(!this->clientHasUuid(uuid, localId)) {
        return crow::response(400, "client ID has not UUID binded");
    }    

    connInfo *conn;

    // verifica se o roteador está conectado ao servidor
    if((conn = webSocketManager.get_connection(uuid)) == nullptr) {
        return crow::response(400, "client UUID not found");
    }

    // ------------- tratar o resto do ip request

    int port;

    if((port = webSocketManager.getConnPort(conn->conn, clientIp)) < 0) {
        return crow::response(400, "Number os ips for this client excceeded");
    }

    // só fazer o ip exchange ...

    return this->exchangeIpPort(conn, port, clientIp, stunRequest);

    // ---------------------------------------------------------------

}

crow::response StunServer::exchangeIpPort(connInfo *conn, int port, const std::string& clientIp, const StunHeader& stunRequest) {
    
    XorMappedAddress xorAddr;
    
    try {
        xorAddr = buildXorMappedAddress(port, clientIp);
    } catch(const std::exception& e) {
        return crow::response(400, "IP inválido");
    }

    json j1 = xorMappedAddressToJsonNlohmann(xorAddr);
    json j2 = stunHeaderToJsonNlohmann(conn->header);

    j1.update(j2);

    j1.update(nlohmann::json{   
        {"status", "exchange"}
    });

    std::cout << "Resposta final JSON (primeiro): " << j1.dump(4) << std::endl;  // dump(4) para identação bonita

    conn->conn->send_text(j1.dump());

    try {
        xorAddr = buildXorMappedAddress(port, conn->conn->get_remote_ip());
    } catch(const std::exception& e) {
        return crow::response(400, "IP Inválido (do outro cliente)");
    }

    j1 = xorMappedAddressToJsonNlohmann(xorAddr);
    j2 = stunHeaderToJsonNlohmann(stunRequest);

    j1.update(j2);

    std::cout << "Resposta final JSON: (primeiro): " << j1.dump(4) << std::endl;

    return crow::response(200, j1.dump());
}

crow::response StunServer::uuidResponse(StunHeader& stunRequest, std::string* authId) {

    // Verifica o token do Google e pega o localId
    if (!firebaseManager->verifyGoogleIdToken(*authId)) {
        std::cout << "Não foi possível autenticar cliente\n";
        return crow::response(400, "Autenticação do Google inválida");
    }

    generateUUIDBytes(stunRequest.uuid);

    return crow::response(200, stunHeaderToJson(stunRequest));
}

crow::response StunServer::removeClient(StunHeader& stunRequest, std::string* authId) {

    std::string localId;
    std::string uuid = bytes_to_hex(stunRequest.uuid, 16);

    if(!firebaseManager->verifyGoogleIdToken(*authId, &localId)) {
        std::cout << "Não foi possível autenticar cliente\n";
        return crow::response(400, "Autenticação do Google inválida");
    }

    std::string response = firebaseManager->sendRequest("users", "", "", GET);
    nlohmann::json jsonData = nlohmann::json::parse(response);

    if (!jsonData.contains("documents")) {
        std::cerr << "Resposta do Firebase não contém documentos: " << response << std::endl;
        return crow::response(400, "error: não foi possível encontrar documento");
    }
    
    if (!jsonContainsUUID(jsonData, uuid)) {
        std::cout << "UUID não encontrado no JSON!" << std::endl;
        return crow::response(400, "error: não foi possível encontrar uuid");
    }

    for (const auto& user : jsonData["documents"]) {
        if (!user.is_object() || !user.contains("fields") || !user["fields"].contains("routers")) {
            continue;
        }

        std::string docName = user["name"];
        if (docName.size() >= localId.size() + 1 &&
            docName.substr(docName.size() - localId.size() - 1) == "/" + localId) {

            nlohmann::json userData = user["fields"];
            auto& routers = userData["routers"]["mapValue"]["fields"];
            
            if (routers.contains(uuid)) {

                std::string fullPath = user["name"];
                std::string userId = fullPath.substr(fullPath.rfind('/') + 1);

                routers.erase(uuid);

                nlohmann::json patchData = {
                    {"fields", {
                        {"routers", userData["routers"]},  // Envia todos os routers
                    }}
                };

                firebaseManager->sendRequest("users", userId, patchData.dump(), PATCH);

                auto conn = webSocketManager.get_connection(uuid);

                json j = stunHeaderToJsonNlohmann(conn->header);
                j.update({{"status", "disconnected"}});

                conn->conn->send_text(j.dump());
                conn->conn->close();

                webSocketManager.remove(uuid);

                return crow::response(200, stunHeaderToJson(stunRequest));

            } else {

                return crow::response(400, stunHeaderToJson(stunRequest));

            }
        }
    }

    return crow::response(400, stunHeaderToJson(stunRequest));
}

crow::response StunServer::getRemoteIp(StunHeader& stunRequest, const std::string clientIp) {

    XorMappedAddress xorAddr;

    try {
        xorAddr = buildXorMappedAddress(0, clientIp);
    } catch(const std::exception& e) {
        return crow::response(400, "IP inválido");
    }

    json j1 = xorMappedAddressToJsonNlohmann(xorAddr);
    json j2 = stunHeaderToJsonNlohmann(stunRequest);

    j1.update(j2);

    std::cout << "Resposta final JSON (primeiro): " << j1.dump(4) << std::endl;  // dump(4) para identação bonita

    return crow::response(200, j1.dump());
}

void StunServer::handleWebSocketMessage(crow::websocket::connection& conn, const std::string& data, bool is_binary) {

    static std::unordered_map<crow::websocket::connection*, std::string> pendingConnections;

    if(!is_binary) {

        try {

            json j = json::parse(data);

            StunHeader stunRequest;

            try {
                stunRequest = jsonNlohmannToStunHeader(j);
            } catch (const std::runtime_error& e) {
                std::cerr << "Erro ao parsear para stunRequest: " << e.what() << std::endl;
                conn.send_text(json{{"status", "error"}, {"message", "Chaves inválidas"}}.dump());
            }


            if (j.contains("auth_id")) {

                std::string auth_id;
                auth_id = j["auth_id"].get<std::string>();

                std::cout << "||||||||||||||||||||||||||||||\n";
                std::cout << auth_id;

                this->detectRequestType(stunRequest, &auth_id, &conn, nullptr);

            } else {

                std::cout << "Ta sem authId\n";

                this->detectRequestType(stunRequest, nullptr, &conn, nullptr);
            }

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

// ============================================= F U N Ç Ã O  P A R A  S A L V A R  U U I D  N O  F I R E B A S E ============================================

bool StunServer::addRouterToUser(const std::string& localId, const std::string& uuid, bool status) {
    // Faz o GET no documento do usuário
    std::string response = firebaseManager->sendRequest("users", localId, "", GET);

    if (response.empty()) {
        std::cout << "Erro na requisição ou sem permissão\n";
        return false;
    }

    json jsonResponse;
    try {
        jsonResponse = json::parse(response);
    } catch (const json::parse_error& e) {
        std::cout << "Erro ao parsear resposta do GET: " << e.what() << std::endl;
        return false;
    }

    json routerJson;

    // Verifica se o documento existe
    if (jsonResponse.empty() || !jsonResponse.contains("fields")) {
        std::cout << "Documento não existe, criando...\n";
        // Cria o JSON para o novo documento com o primeiro router
        routerJson = {
            {"fields", {
                {"routers", {
                    {"mapValue", {
                        {"fields", {
                            {uuid, {
                                {"mapValue", {
                                    {"fields", {
                                        {"type", {{"stringValue", "DM956_1800GT"}}},
                                        {"activity", {{"booleanValue", status}}}
                                    }}
                                }}
                            }}
                        }}
                    }}
                }}
            }}
        };
        // Tenta criar o documento com POST
        std::string response_2 = firebaseManager->sendRequest("users", localId, routerJson.dump(), POST);
        std::cout << "Resposta da criação: " << response_2 << std::endl;

        // Verifica se houve erro 409 (documento já existe)
        if (!response_2.empty()) {
            json postResponse;
            try {
                postResponse = json::parse(response_2);
            } catch (const json::parse_error& e) {
                std::cout << "Erro ao parsear resposta do POST: " << e.what() << std::endl;
                return false;
            }

            if (postResponse.contains("error") && postResponse["error"]["code"] == 409) {
                std::cout << "Documento já existe, tentando atualizar...\n";
                // Faz outro GET pra pegar o estado atual do documento
                std::string getResponse = firebaseManager->sendRequest("users", localId, "", GET);
                if (getResponse.empty()) {
                    std::cout << "Erro na requisição GET após erro 409\n";
                    return false;
                }

                json getJsonResponse;
                try {
                    getJsonResponse = json::parse(getResponse);
                } catch (const json::parse_error& e) {
                    std::cout << "Erro ao parsear resposta do GET: " << e.what() << std::endl;
                    return false;
                }

                // Pega o mapa routers atual, se existir
                json currentRouters;
                if (getJsonResponse.contains("fields") && getJsonResponse["fields"].contains("routers") && 
                    getJsonResponse["fields"]["routers"].contains("mapValue")) {
                    currentRouters = getJsonResponse["fields"]["routers"]["mapValue"]["fields"];
                } else {
                    currentRouters = json::object();  // Cria um mapa vazio se não existir
                }

                // Adiciona o novo router ao mapa
                currentRouters[uuid] = {
                    {"mapValue", {
                        {"fields", {
                            {"type", {{"stringValue", "DM956_1800GT"}}},
                            {"activity", {{"booleanValue", status}}}
                        }}
                    }}
                };

                // Monta o JSON atualizado com o mapa routers completo
                routerJson = {
                    {"fields", {
                        {"routers", {
                            {"mapValue", {
                                {"fields", currentRouters}
                            }}
                        }}
                    }}
                };

                // Faz o PATCH pra atualizar o documento
                std::string patchResponse = firebaseManager->sendRequest("users", localId, routerJson.dump(), PATCH);
                std::cout << "Resposta da atualização: " << patchResponse << std::endl;

                // Verifica se o PATCH foi bem-sucedido
                if (!patchResponse.empty()) {
                    json patchJsonResponse;
                    try {
                        patchJsonResponse = json::parse(patchResponse);
                        if (!patchJsonResponse.contains("error")) {
                            return true;
                        } else {
                            std::cout << "Erro no PATCH: " << patchJsonResponse["error"]["message"] << std::endl;
                            return false;
                        }
                    } catch (const json::parse_error& e) {
                        std::cout << "Erro ao parsear resposta do PATCH: " << e.what() << std::endl;
                        return false;
                    }
                }
                return false;
            } else if (!postResponse.contains("error")) {
                // POST bem-sucedido
                return true;
            } else {
                // Outro erro no POST
                std::cout << "Erro na criação: " << postResponse["error"]["message"] << std::endl;
                return false;
            }
        }
        std::cout << "Resposta vazia na criação\n";
        return false;
    } else {
        std::cout << "Documento existe, atualizando...\n";
        // Pega o mapa routers atual, se existir
        json currentRouters;
        if (jsonResponse["fields"].contains("routers") && jsonResponse["fields"]["routers"].contains("mapValue")) {
            currentRouters = jsonResponse["fields"]["routers"]["mapValue"]["fields"];
        } else {
            currentRouters = json::object();  // Cria um mapa vazio se não existir
        }

        // Adiciona o novo router ao mapa
        currentRouters[uuid] = {
            {"mapValue", {
                {"fields", {
                    {"type", {{"stringValue", "DM956_1800GT"}}},
                    {"activity", {{"booleanValue", status}}}
                }}
            }}
        };

        // Monta o JSON atualizado com o mapa routers completo
        routerJson = {
            {"fields", {
                {"routers", {
                    {"mapValue", {
                        {"fields", currentRouters}
                    }}
                }}
            }}
        };

        // Faz o PATCH pra atualizar o documento
        std::string response_2 = firebaseManager->sendRequest("users", localId, routerJson.dump(), PATCH);
        std::cout << "Resposta da atualização: " << response_2 << std::endl;

        // Verifica se o PATCH foi bem-sucedido
        if (!response_2.empty()) {
            json patchJsonResponse;
            try {
                patchJsonResponse = json::parse(response_2);
                if (!patchJsonResponse.contains("error")) {
                    return true;
                } else {
                    std::cout << "Erro no PATCH: " << patchJsonResponse["error"]["message"] << std::endl;
                    return false;
                }
            } catch (const json::parse_error& e) {
                std::cout << "Erro ao parsear resposta do PATCH: " << e.what() << std::endl;
                return false;
            }
        }
        return false;
    }
}