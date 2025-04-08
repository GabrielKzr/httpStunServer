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

std::string FirebaseManager::sendRequest(const std::string& collection, const std::string& document, const std::string& jsonData, int method) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;

    const std::string methodStr = methodToString(method);

    std::string url = FIRESTORE_URL + collection + "/" + document + "?key=" + FIREBASE_API_KEY;

    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Erro ao inicializar o cURL" << std::endl;
        return "";
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");

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

bool FirebaseManager::verifyGoogleIdToken(const std::string& idToken, std::string* outLocalId = nullptr) {
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
