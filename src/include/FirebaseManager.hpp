#ifndef FIREBASE_MANAGER_HPP
#define FIREBASE_MANAGER_HPP

#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp> 
#include <fstream>
#include <ctime>
#include <jwt-cpp/jwt.h>

#pragma once

enum HttpMethods {
    POST,
    GET,
    PUT,
    DELETE,
    PATCH
};

const char* methodToString(int method);

class FirebaseManager {
    
public: 
    
    FirebaseManager(std::string project_id, std::string api_key, std::string pathToAdmJson);
    
    std::string sendRequest(const std::string& collection, const std::string& document, const std::string& jsonData, int method);
    bool verifyGoogleIdToken(const std::string& idToken, std::string* outLocalId = nullptr);
    bool getFirebaseAccessToken(const std::string& jsonPath);

private:

    std::string FIREBASE_PROJECT_ID;
    std::string FIREBASE_API_KEY;
    std::string FIRESTORE_URL;
    std::string FIREBASE_VERIFY_TOKEN_URL;
    std::string firebaseAccessToken;
};

#endif // FIREBASE_MANAGER_HPP
