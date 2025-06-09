#include "src/include/FirebaseApi.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

FirebaseApi::FirebaseApi(std::string project_id, std::string api_key, std::string pathToAdmJson) {
    firebaseManager = new FirebaseManager(project_id, api_key, pathToAdmJson);

    // Verifica e cria as coleções 'users', 'devices' e 'routers' se não existirem
    std::vector<std::string> collections = {"users", "devices", "routers"};
    for (const auto& collection : collections) {
        std::string resp = firebaseManager->sendRequest(collection, "", "", GET);
        if (resp.empty()) {
            nlohmann::json dummy;
            dummy["fields"]["dummy"]["stringValue"] = "init";
            firebaseManager->sendRequest(collection, "init_doc", dummy.dump(), PATCH);
            std::cout << "Coleção '" << collection << "' criada no Firestore." << std::endl;
        } else {
            std::cout << "Coleção '" << collection << "' já existe no Firestore." << std::endl;
        }
    }

    // Agora, valida os documentos existentes
    std::string usersResp = firebaseManager->sendRequest("users", "", "", GET);
    if (!usersResp.empty()) {
        nlohmann::json usersJson = nlohmann::json::parse(usersResp);
        if (usersJson.contains("documents")) {
            for (const auto& userDoc : usersJson["documents"]) {
                // Extrai UID do nome do documento
                std::string userName = userDoc["name"];
                std::string uid = userName.substr(userName.find_last_of('/') + 1);

                // Verifica arrays de devices e routers
                auto fields = userDoc["fields"];
                std::vector<std::string> deviceTokens, routerUuids;

                if (fields.contains("devices")) {
                    auto devicesArr = fields["devices"]["arrayValue"].value("values", nlohmann::json::array());
                    for (const auto& d : devicesArr) {
                        std::string token = d.value("stringValue", "");
                        if (!token.empty()) deviceTokens.push_back(token);
                    }
                }
                if (fields.contains("routers")) {
                    auto routersArr = fields["routers"]["arrayValue"].value("values", nlohmann::json::array());
                    for (const auto& r : routersArr) {
                        std::string uuid = r.value("stringValue", "");
                        if (!uuid.empty()) routerUuids.push_back(uuid);
                    }
                }

                // Para cada device, verifica se existe e está mapeado corretamente
                for (const auto& token : deviceTokens) {
                    std::string deviceResp = firebaseManager->sendRequest("devices", token, "", GET);
                    if (deviceResp.empty()) {
                        // Cria o device se não existir
                        nlohmann::json deviceJson;
                        deviceJson["fields"]["uid"]["stringValue"] = uid;
                        firebaseManager->sendRequest("devices", token, deviceJson.dump(), PATCH);
                    } else {
                        // Atualiza o uid se necessário
                        nlohmann::json deviceJson = nlohmann::json::parse(deviceResp);
                        if (!deviceJson["fields"].contains("uid") || deviceJson["fields"]["uid"]["stringValue"] != uid) {
                            nlohmann::json updateJson;
                            updateJson["fields"]["uid"]["stringValue"] = uid;
                            firebaseManager->sendRequest("devices", token, updateJson.dump(), PATCH);
                        }
                    }
                }

                // Para cada router, verifica se existe, está mapeado corretamente e status = false
                for (const auto& uuid : routerUuids) {
                    std::string routerResp = firebaseManager->sendRequest("routers", uuid, "", GET);
                    if (routerResp.empty()) {
                        // Cria o router se não existir
                        nlohmann::json routerJson;
                        routerJson["fields"]["uid"]["stringValue"] = uid;
                        routerJson["fields"]["status"]["booleanValue"] = false;
                        firebaseManager->sendRequest("routers", uuid, routerJson.dump(), PATCH);
                    } else {
                        // Atualiza o uid e status se necessário
                        nlohmann::json routerJson = nlohmann::json::parse(routerResp);
                        bool needsUpdate = false;
                        nlohmann::json updateJson;
                        if (!routerJson["fields"].contains("uid") || routerJson["fields"]["uid"]["stringValue"] != uid) {
                            updateJson["fields"]["uid"]["stringValue"] = uid;
                            needsUpdate = true;
                        }
                        if (!routerJson["fields"].contains("status") || routerJson["fields"]["status"]["booleanValue"] != false) {
                            updateJson["fields"]["status"]["booleanValue"] = false;
                            needsUpdate = true;
                        }
                        if (needsUpdate) {
                            firebaseManager->sendRequest("routers", uuid, updateJson.dump(), PATCH);
                        }
                    }
                }
            }
        }
    }
}

FirebaseApi::~FirebaseApi() {
    delete firebaseManager;
}

// Adiciona um router ao vetor de routers do usuário
bool FirebaseApi::addRouterToUser(const std::string& uid, const std::string& routerUuid, bool status) {
    // 1. Atualiza o vetor de routers do usuário
    std::string userDoc = "users/" + uid;
    std::string userGetResp = firebaseManager->sendRequest("users", uid, "", GET);
    if (userGetResp.empty()) return false;

    json userJson = json::parse(userGetResp);
    auto routers = userJson["fields"].contains("routers") ? userJson["fields"]["routers"]["arrayValue"]["values"] : json::array();
    bool alreadyExists = false;
    for (const auto& r : routers) {
        if (r["stringValue"] == routerUuid) {
            alreadyExists = true;
            break;
        }
    }
    if (!alreadyExists) {
        routers.push_back({{"stringValue", routerUuid}});
    } else {
        return false;
    }

    json updateUser;
    updateUser["fields"]["routers"]["arrayValue"]["values"] = routers;
    firebaseManager->sendRequest("users", uid, updateUser.dump(), PATCH);

    // 2. Cria/atualiza o router
    json routerJson;
    routerJson["fields"]["status"]["booleanValue"] = status;
    routerJson["fields"]["uid"]["stringValue"] = uid;
    routerJson["fields"]["uuid"]["stringValue"] = "DM956_1800GT"; 
    // routerJson["fields"]["modelo"]["stringValue"] = ...; // Adicione se necessário

    firebaseManager->sendRequest("routers", routerUuid, routerJson.dump(), PATCH);

    return true;
} // VERIFIQUEI E FAZ SENTIDO

// Remove um router do vetor de routers do usuário
bool FirebaseApi::removeRouterFromUser(const std::string& uid, const std::string& routerUuid) {
    // 1. Remove do vetor do usuário
    std::string userGetResp = firebaseManager->sendRequest("users", uid, "", GET);
    if (userGetResp.empty()) return false;

    json userJson = json::parse(userGetResp);
    auto routers = userJson["fields"].contains("routers") ? userJson["fields"]["routers"]["arrayValue"]["values"] : json::array();
    json newRouters = json::array();
    for (const auto& r : routers) {
        if (r["stringValue"] != routerUuid) {
            newRouters.push_back(r);
        }
    }
    json updateUser;
    updateUser["fields"]["routers"]["arrayValue"]["values"] = newRouters;
    firebaseManager->sendRequest("users", uid, updateUser.dump(), PATCH);

    // 2. Remove o router do banco
    firebaseManager->sendRequest("routers", routerUuid, "", DELETE);

    return true;
} // VERIFIQUEI E FAZ SENTIDO

// Verifica se o usuário possui determinado router
bool FirebaseApi::clientHasUuid(const std::string& routerUuid, const std::string& uid) {
    std::string userGetResp = firebaseManager->sendRequest("users", uid, "", GET);
    if (userGetResp.empty()) return false;

    json userJson = json::parse(userGetResp);
    if (!userJson["fields"].contains("routers")) return false;
    auto routers = userJson["fields"]["routers"]["arrayValue"]["values"];
    for (const auto& r : routers) {
        if (r["stringValue"] == routerUuid) return true;
    }
    return false;
} // VERIFIQUEI E FAZ SENTIDO

// Adiciona um device ao usuário
bool FirebaseApi::addDeviceToUser(const std::string& uid, const std::string& deviceToken) {
    // 1. Atualiza o vetor de devices do usuário
    std::string userGetResp = firebaseManager->sendRequest("users", uid, "", GET);
    if (userGetResp.empty()) return false;

    json userJson = json::parse(userGetResp);
    auto devices = userJson["fields"].contains("devices") ? userJson["fields"]["devices"]["arrayValue"]["values"] : json::array();
    bool alreadyExists = false;
    for (const auto& d : devices) {
        if (d["stringValue"] == deviceToken) {
            alreadyExists = true;
            break;
        }
    }
    if (!alreadyExists) {
        devices.push_back({{"stringValue", deviceToken}});
    } else {
        return false;
    }

    json updateUser;
    updateUser["fields"]["devices"]["arrayValue"]["values"] = devices;
    firebaseManager->sendRequest("users", uid, updateUser.dump(), PATCH);

    // 2. Cria/atualiza o device
    json deviceJson;
    deviceJson["fields"]["uid"]["stringValue"] = uid;
    firebaseManager->sendRequest("devices", deviceToken, deviceJson.dump(), PATCH);

    return true;
} // VERIFIQUEI E FAZ SENTIDO

// Remove um device do usuário
bool FirebaseApi::removeDeviceFromUser(const std::string& uid, const std::string& deviceToken) {
    // 1. Remove do vetor do usuário
    std::string userGetResp = firebaseManager->sendRequest("users", uid, "", GET);
    if (userGetResp.empty()) return false;

    json userJson = json::parse(userGetResp);
    auto devices = userJson["fields"].contains("devices") ? userJson["fields"]["devices"]["arrayValue"]["values"] : json::array();
    json newDevices = json::array();
    for (const auto& d : devices) {
        if (d["stringValue"] != deviceToken) {
            newDevices.push_back(d);
        }
    }
    json updateUser;
    updateUser["fields"]["devices"]["arrayValue"]["values"] = newDevices;
    firebaseManager->sendRequest("users", uid, updateUser.dump(), PATCH);

    // 2. Remove o device do banco
    firebaseManager->sendRequest("devices", deviceToken, "", DELETE);

    return true;
} // VERIFIQUEI E FAZ SENTIDO

// Verifica se o device pertence ao usuário
bool FirebaseApi::userHasDevice(const std::string& uid, const std::string& deviceToken) {
    std::string userGetResp = firebaseManager->sendRequest("users", uid, "", GET);
    if (userGetResp.empty()) return false;

    json userJson = json::parse(userGetResp);
    if (!userJson["fields"].contains("devices")) return false;
    auto devices = userJson["fields"]["devices"]["arrayValue"]["values"];
    for (const auto& d : devices) {
        if (d["stringValue"] == deviceToken) return true;
    }
    return false;
} // VERIFIQUEI E FAZ SENTIDO