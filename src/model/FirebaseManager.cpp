#include "../include/FirebaseManager.hpp"

using json = nlohmann::json;

const char* methodToString(int method) {
    switch (method) {
        case POST: return "POST";
        case GET: return "GET";
        case PUT: return "PUT";
        case DELETE: return "DELETE";
        case PATCH: return "PATCH";
        default: return "Unknown";
    }
}

FirebaseManager::FirebaseManager(std::string project_id, std::string api_key, std::string pathToAdmJson) : FIREBASE_PROJECT_ID(std::move(project_id)), FIREBASE_API_KEY(std::move(api_key)) {

    jsonPath = pathToAdmJson;
    stopFlag = false;

    FIRESTORE_URL = "https://firestore.googleapis.com/v1/projects/" + FIREBASE_PROJECT_ID + "/databases/(default)/documents/";
    FIREBASE_VERIFY_TOKEN_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + FIREBASE_API_KEY;

    if(!this->getFirebaseAccessToken(pathToAdmJson)) {
        throw std::runtime_error("Falha ao obter token de acesso Firebase");
    }

    renewalThread = std::thread(&FirebaseManager::renewalLoop, this);
    renewalThread.detach();
}

std::string FirebaseManager::sendRequest(const std::string& collection, const std::string& document, const std::string& jsonData, int method) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;

    const std::string methodStr = methodToString(method);
    std::string url;

    // Montagem inteligente da URL
    if (document.empty()) {
        // Criar documento com ID automático
        url = FIRESTORE_URL + collection;
    } else {
        if (methodStr == "POST") {
            // Criar com ID específico
            url = FIRESTORE_URL + collection + "?documentId=" + document;
        } else {
            // PUT ou GET/DELETE para documento específico
            url = FIRESTORE_URL + collection + "/" + document;
        }
    }

    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Erro ao inicializar o cURL" << std::endl;
        return "";
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("Authorization: Bearer " + firebaseAccessToken).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, methodStr.c_str());

    if (methodStr != "GET" && methodStr != "DELETE") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void *ptr, size_t size, size_t nmemb, std::string *data) -> size_t {
        data->append(reinterpret_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
    });

    std::string responseData;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseData);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "Erro no cURL: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        return "";
    }

    std::cout << methodStr << " enviado com sucesso!" << std::endl;

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return responseData;
}

bool FirebaseManager::verifyGoogleIdToken(const std::string& idToken, std::string* outLocalId) {
    CURL* curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        curl_global_cleanup();
        return false;
    }

    // Construindo JSON com nlohmann
    json payload;
    payload["idToken"] = idToken;
    std::string jsonData = payload.dump();

    curl_easy_setopt(curl, CURLOPT_URL, FIREBASE_VERIFY_TOKEN_URL.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    std::string readBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        static_cast<std::string*>(userp)->append(contents, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        std::cerr << "Erro ao verificar token: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        curl_global_cleanup();
        return false;
    }

    std::cout << "Resposta do Firebase: " << readBuffer << std::endl;

    try {
        json jsonResponse = json::parse(readBuffer);

        if (jsonResponse.contains("error")) {
            std::cerr << "Erro na validação do token: " << jsonResponse["error"]["message"] << std::endl;
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            curl_global_cleanup();
            return false;
        } 

        if (jsonResponse.contains("users") && !jsonResponse["users"].empty()) {
            if (outLocalId) {
                *outLocalId = jsonResponse["users"][0]["localId"].get<std::string>();
            }
            std::cout << "Token válido! localId: " << outLocalId << std::endl;
            return true;
        } else {
            std::cerr << "Campo 'users' não encontrado ou vazio na resposta do Firebase." << std::endl;
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            curl_global_cleanup();
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Erro ao processar JSON: " << e.what() << std::endl;
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        curl_global_cleanup();
        return false;
    }
}

bool FirebaseManager::getFirebaseAccessToken(const std::string& jsonPath) {
    // Ler chave do JSON
    std::ifstream file(jsonPath);
    if (!file.is_open()) {
        std::cerr << "Erro ao abrir o JSON da conta de serviço.\n";
        return "";
    }
    
    nlohmann::json keyJson = nlohmann::json::parse(file);
    std::string private_key = keyJson["private_key"];
    std::string client_email = keyJson["client_email"];
    std::string token_uri = keyJson["token_uri"];

    // Tempo atual
    auto now = std::chrono::system_clock::now();
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    // Criar JWT
    auto token = jwt::create()
        .set_issuer(client_email)
        .set_audience(token_uri)
        .set_issued_at(std::chrono::system_clock::from_time_t(now_sec))
        .set_expires_at(std::chrono::system_clock::from_time_t(now_sec + 3600))
        .set_payload_claim("scope", jwt::claim(std::string("https://www.googleapis.com/auth/datastore")));

    // Assinar JWT
    std::string jwt_token;
    try {
        jwt_token = token.sign(jwt::algorithm::rs256("", private_key, "", ""));
    } catch (const std::exception& e) {
        std::cerr << "Erro ao assinar JWT: " << e.what() << "\n";
        return "";
    }

    // Fazer requisição POST para o token_uri
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Erro ao inicializar curl\n";
        return "";
    }

    std::string postFields = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + std::string(curl_easy_escape(curl, jwt_token.c_str(), 0));
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, token_uri.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* ptr, size_t size, size_t nmemb, std::string* data) -> size_t {
        data->append(reinterpret_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
    });

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        std::cerr << "Erro na requisição do token: " << curl_easy_strerror(res) << "\n";
        return "";
    }

    // Parse da resposta
    auto jsonResp = nlohmann::json::parse(response);
    if (jsonResp.contains("access_token")) {
        firebaseAccessToken = jsonResp["access_token"];
        // std::cout << "Firebase access token: " << firebaseAccessToken << std::endl;
        return true;
    } else {
        std::cerr << "Resposta inválida:\n" << response << "\n";
        firebaseAccessToken = "";
        return false;
    }
}

void FirebaseManager::renewalLoop() {
    using namespace std::chrono;
    while (!stopFlag) {
        // calcula o ponto no tempo exato para próxima renovação:
        auto next = system_clock::now() + minutes(57);
        
        // dorme até lá, mas acorda se stopFlag mudar
        while (!stopFlag && system_clock::now() < next) {
            std::this_thread::sleep_for(minutes(1));
        }
        
        if (stopFlag) break;
        
        // renova o token
        if (!getFirebaseAccessToken(jsonPath)) {
            std::cerr << "Erro ao renovar token\n";
        }
    }
}

FirebaseManager::~FirebaseManager() {
    stopFlag = true;
}