#include "src/include/FirebaseApi.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

FirebaseApi::FirebaseApi(std::string project_id, std::string api_key, std::string pathToAdmJson) {
    firebaseManager = new FirebaseManager(project_id, api_key, pathToAdmJson);
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
    }

    json updateUser;
    updateUser["fields"]["routers"]["arrayValue"]["values"] = routers;
    firebaseManager->sendRequest("users", uid, updateUser.dump(), PATCH);

    // 2. Cria/atualiza o router
    json routerJson;
    routerJson["fields"]["status"]["booleanValue"] = status;
    routerJson["fields"]["uid"]["stringValue"] = uid;
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
    }

    json updateUser;
    updateUser["fields"]["devices"]["arrayValue"]["values"] = devices;
    firebaseManager->sendRequest("users", uid, updateUser.dump(), PATCH);

    // 2. Cria/atualiza o device
    json deviceJson;
    deviceJson["fields"]["uid"]["stringValue"] = uid;
    firebaseManager->sendRequest("devices", deviceToken, deviceJson.dump(), PATCH);

    return true;
}

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
}

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
}