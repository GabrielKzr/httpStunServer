#ifndef FIREBASE_MANAGER_HPP
#define FIREBASE_MANAGER_HPP

#include <iostream>
#include <curl/curl.h>
#include <json/json.h>

#pragma once

enum HttpMethods {
    POST,
    GET,
    PUT,
    DELETE,
    PATCH
};

// Declaração da função
const char* methodToString(int method);

class FirebaseManager {
    
public: 
    
    FirebaseManager(std::string project_id, std::string api_key)
        : FIREBASE_PROJECT_ID(std::move(project_id)), FIREBASE_API_KEY(std::move(api_key)) {
        FIRESTORE_URL = "https://firestore.googleapis.com/v1/projects/" + FIREBASE_PROJECT_ID + "/databases/(default)/documents/";
        FIREBASE_VERIFY_TOKEN_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + FIREBASE_API_KEY;
    }

    std::string sendRequest(const std::string& collection, const std::string& document, const std::string& jsonData, int method);
    bool verifyGoogleIdToken(const std::string& idToken);

private:

    std::string FIREBASE_PROJECT_ID;
    std::string FIREBASE_API_KEY;
    std::string FIRESTORE_URL;
    std::string FIREBASE_VERIFY_TOKEN_URL;
};

#endif // FIREBASE_MANAGER_HPP
